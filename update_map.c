#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dirent.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include "policy.h"

// 检查是否支持bpf_obj_get_by_id函数
#ifndef BPF_OBJ_GET_BY_ID
#define BPF_OBJ_GET_BY_ID 0
#endif

#ifndef BPF_MAP_GET_FD_BY_ID
#define BPF_MAP_GET_FD_BY_ID 7
#endif

// 白名单方向位掩码：1=入向，2=出向
#define MODE_INGRESS 1
#define MODE_EGRESS  2

// 固定 map 路径：用于不同进程共享 eBPF map
static const char *PIN_NET_POLICY = "/sys/fs/bpf/tc_filter_net_policy";
static const char *PIN_POLICY_MODE = "/sys/fs/bpf/tc_filter_policy_mode";
// endpoint 级规则外层 map 固定路径（key=ifindex）
static const char *PIN_ENDPOINT_RULES = "/sys/fs/bpf/tc_filter_endpoint_rules";
// CIDR 规则 map 固定路径
static const char *PIN_CIDR_SRC_POLICY = "/sys/fs/bpf/tc_filter_cidr_src_policy";
static const char *PIN_CIDR_DST_POLICY = "/sys/fs/bpf/tc_filter_cidr_dst_policy";

#define CIDR_KEY_BITS 112
#define CIDR_REST_BITS 80

static int pin_map_replace(int fd, const char *path, const char *label) {
    if (bpf_obj_pin(fd, path) == 0) {
        printf("%s pinned to %s\n", label, path);
        return 0;
    }
    if (errno == EEXIST) {
        if (unlink(path) != 0) {
            fprintf(stderr, "Failed to remove existing %s pin at %s: %s\n", label, path, strerror(errno));
            return -1;
        }
        if (bpf_obj_pin(fd, path) == 0) {
            printf("%s re-pinned to %s\n", label, path);
            return 0;
        }
    }
    fprintf(stderr, "Failed to pin %s: %s\n", label, strerror(errno));
    return -1;
}

/*
 * 判断网卡接口是否存在，避免对不存在接口挂载 tc。
 */
static int interface_exists(const char *iface) {
    if (!iface || iface[0] == '\0') {
        return 0;
    }
    if (if_nametoindex(iface) != 0) {
        return 1;
    }
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s", iface);
    return access(path, F_OK) == 0;
}

/*
 * 在指定网卡上挂载 ingress/egress tc 过滤器。
 */
static void attach_tc_to_iface(const char *iface, const char *pin_path) {
    if (!interface_exists(iface)) {
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact 2>/dev/null", iface);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "tc filter add dev %s ingress bpf object-pinned %s da", iface, pin_path);
    printf("执行挂载ingress: %s\n", cmd);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "tc filter add dev %s egress bpf object-pinned %s da", iface, pin_path);
    printf("执行挂载egress: %s\n", cmd);
    system(cmd);
}

/*
 * 遍历所有 veth* / cali* 接口并挂载 tc，覆盖同节点 Pod<->Pod 流量。
 */
static void attach_tc_to_all_veth(const char *pin_path) {
    DIR *dir = opendir("/sys/class/net");
    if (!dir) {
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "veth", 4) == 0 || strncmp(ent->d_name, "cali", 4) == 0) {
            attach_tc_to_iface(ent->d_name, pin_path);
        }
    }
    closedir(dir);
}

/*
 * 提升进程的内存锁定上限，确保 eBPF 资源可用。
 */
void bump_memlock() {
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
        fprintf(stderr, "警告: 无法提升 RLIMIT_MEMLOCK 限制\n");
    } 
}

static int is_cidr(const char *ip_str) {
    return ip_str && strchr(ip_str, '/') != NULL;
}

static int parse_cidr(const char *cidr_str, __u32 *ip, __u32 *prefix) {
    if (!cidr_str || !ip || !prefix) {
        return -1;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", cidr_str);
    char *slash = strchr(buf, '/');
    if (!slash) {
        return -1;
    }
    *slash = '\0';
    int plen = atoi(slash + 1);
    if (plen < 0 || plen > 32) {
        return -1;
    }
    __u32 ip_net = 0;
    if (inet_pton(AF_INET, buf, &ip_net) != 1) {
        return -1;
    }
    __u32 ip_host = ntohl(ip_net);
    __u32 mask = (plen == 0) ? 0 : (0xFFFFFFFFu << (32 - plen));
    ip_host &= mask;
    *ip = htonl(ip_host);
    *prefix = (__u32)plen;
    return 0;
}

static void build_cidr_key(struct cidr_key *key, __u32 ip, __u32 other_ip, __u32 prefix_len, __u16 port, __u8 proto) {
    memset(key, 0, sizeof(*key));
    if (prefix_len < 32) {
        key->prefixlen = prefix_len;
    } else {
        key->prefixlen = 32 + CIDR_REST_BITS;
    }
    key->ip = ip;
    key->other_ip = other_ip;
    key->port = htons(port);
    key->proto = proto;
}

// // 与eBPF程序中的结构体定义一致
// struct flow_key {
//     __u32 src_ip;
//     __u32 dst_ip;
//     __u16 port;
//     __u8 proto;
// } __attribute__((packed));

// struct flow_value {
//     __u8 action;  // 0: accept, 1: drop
//     __u32 counter;
// } __attribute__((packed));

// startEBPF函数 - 加载并启动BPF程序，同时固定map以便后续更新
/*
 * 加载并启动 eBPF 程序，固定程序与 map，并挂载 tc 规则。
 */
void startEBPF(const char *interface_name) {
    bump_memlock();

    // 清理旧的资源
    printf("Cleaning up old resources...\n");
    char cmd[512];
    
    // 删除所有可能的旧固定点
    snprintf(cmd, sizeof(cmd), "rm -f /sys/fs/bpf/net_policy /sys/fs/bpf/tc_filter_net_policy /sys/fs/bpf/tc_filter_policy_mode /sys/fs/bpf/tc_filter_endpoint_rules /sys/fs/bpf/my_tc_prog 2>/dev/null");
    system(cmd);
    
    // 删除旧的tc规则
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", interface_name);
    system(cmd);
    
    // 清理可能存在的BPF程序
    snprintf(cmd, sizeof(cmd), "tc filter del dev %s ingress 2>/dev/null", interface_name);
    system(cmd);

    // 清理可能存在的BPF程序
    snprintf(cmd, sizeof(cmd), "tc filter del dev %s egress 2>/dev/null", interface_name);
    system(cmd);

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int prog_fd = -1;
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/net_policy");

    // 1. 打开BPF对象文件（只加载tc_filter.bpf.o）
    obj = bpf_object__open_file("tc_filter.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return;
    }

    // 设置严格模式以提高兼容性
    libbpf_set_strict_mode(LIBBPF_STRICT_NONE);

    // 2. 加载BPF对象
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return;
    }

    // 3. 获取程序fd并固定到BPF文件系统
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(obj);
        return;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        bpf_object__close(obj);
        return;
    }

    // 4. 固定BPF程序到文件系统
    if (bpf_obj_pin(prog_fd, pin_path) != 0) {
        fprintf(stderr, "无法固定 BPF 程序到 %s\n", pin_path);
        bpf_object__close(obj);
        return;
    }

    printf("BPF program pinned to %s\n", pin_path);

    // 5. 获取map fd并固定map
    int map_fd = bpf_object__find_map_fd_by_name(obj, "net_policy");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map 'net_policy'\n");
    } else {
        // 固定map到相同路径
        char map_pin_path[256];
        snprintf(map_pin_path, sizeof(map_pin_path), "%s", PIN_NET_POLICY);
        
        pin_map_replace(map_fd, map_pin_path, "Map");
    }

    // 固定 policy_mode map
    int mode_fd = bpf_object__find_map_fd_by_name(obj, "policy_mode");
    if (mode_fd < 0) {
        fprintf(stderr, "Failed to find map 'policy_mode'\n");
    } else {
        char mode_pin_path[256];
        snprintf(mode_pin_path, sizeof(mode_pin_path), "%s", PIN_POLICY_MODE);
        pin_map_replace(mode_fd, mode_pin_path, "Policy mode map");
    }

    // 固定 endpoint_rules 外层 map
    int endpoint_fd = bpf_object__find_map_fd_by_name(obj, "endpoint_rules");
    if (endpoint_fd < 0) {
        fprintf(stderr, "Failed to find map 'endpoint_rules'\n");
    } else {
        char endpoint_pin_path[256];
        snprintf(endpoint_pin_path, sizeof(endpoint_pin_path), "%s", PIN_ENDPOINT_RULES);
        pin_map_replace(endpoint_fd, endpoint_pin_path, "Endpoint rules map");
    }

    // 固定 CIDR src/dst map
    int cidr_src_fd = bpf_object__find_map_fd_by_name(obj, "cidr_src_policy");
    if (cidr_src_fd < 0) {
        fprintf(stderr, "Failed to find map 'cidr_src_policy'\n");
    } else {
        pin_map_replace(cidr_src_fd, PIN_CIDR_SRC_POLICY, "CIDR src map");
    }

    int cidr_dst_fd = bpf_object__find_map_fd_by_name(obj, "cidr_dst_policy");
    if (cidr_dst_fd < 0) {
        fprintf(stderr, "Failed to find map 'cidr_dst_policy'\n");
    } else {
        pin_map_replace(cidr_dst_fd, PIN_CIDR_DST_POLICY, "CIDR dst map");
    }

    // 6. 挂载BPF程序到tc（主接口 + 常见桥接口 + 默认所有 veth）
    attach_tc_to_iface(interface_name, pin_path);
    attach_tc_to_iface("cni0", pin_path);
    attach_tc_to_iface("flannel.1", pin_path);
    attach_tc_to_iface("docker0", pin_path);
    attach_tc_to_iface("cbr0", pin_path);
    attach_tc_to_iface("tunl0", pin_path);
    attach_tc_to_all_veth(pin_path);

    bpf_object__close(obj);
}

// addRule函数 - 实现原main()功能
/*
 * 添加或更新一条规则到 eBPF map。
 */
static void addCidrRule(char *src_str, char *dst_str, int port, int proto, char *action_str) {
    int src_cidr = is_cidr(src_str);
    int dst_cidr = is_cidr(dst_str);
    if (src_cidr && dst_cidr) {
        fprintf(stderr, "CIDR rules do not support both src and dst as CIDR in one rule.\n");
        return;
    }

    struct cidr_key key = {0};
    struct flow_value val = {0};
    __u32 ip = 0;
    __u32 prefix = 0;
    __u32 other_ip = 0;

    if (src_cidr) {
        if (parse_cidr(src_str, &ip, &prefix) != 0) {
            fprintf(stderr, "Invalid src CIDR: %s\n", src_str);
            return;
        }
        if (inet_pton(AF_INET, dst_str, &other_ip) != 1) {
            fprintf(stderr, "Invalid dst IP: %s\n", dst_str);
            return;
        }
        build_cidr_key(&key, ip, other_ip, prefix, port, (__u8)proto);
    } else if (dst_cidr) {
        if (parse_cidr(dst_str, &ip, &prefix) != 0) {
            fprintf(stderr, "Invalid dst CIDR: %s\n", dst_str);
            return;
        }
        if (inet_pton(AF_INET, src_str, &other_ip) != 1) {
            fprintf(stderr, "Invalid src IP: %s\n", src_str);
            return;
        }
        build_cidr_key(&key, ip, other_ip, prefix, port, (__u8)proto);
    }

    if (strcmp(action_str, "drop") == 0) {
        val.action = 1;
    } else {
        val.action = 0;
    }

    const char *map_path = src_cidr ? PIN_CIDR_SRC_POLICY : PIN_CIDR_DST_POLICY;
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get pinned CIDR map. Please run './update_map start <interface>' first.\n");
        return;
    }

    int err = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update CIDR rule: %s (error code: %d)\n", strerror(errno), err);
        close(map_fd);
        return;
    }

    printf("CIDR rule updated: Src=%s Dst=%s Port=%d Proto=%d Action=%s\n",
           src_str, dst_str, port, proto, action_str);
    close(map_fd);
}

static void deleteCidrRule(char *src_str, char *dst_str, int port, int proto) {
    int src_cidr = is_cidr(src_str);
    int dst_cidr = is_cidr(dst_str);
    if (src_cidr && dst_cidr) {
        fprintf(stderr, "CIDR rules do not support both src and dst as CIDR in one rule.\n");
        return;
    }

    struct cidr_key key = {0};
    __u32 ip = 0;
    __u32 prefix = 0;
    __u32 other_ip = 0;

    if (src_cidr) {
        if (parse_cidr(src_str, &ip, &prefix) != 0) {
            fprintf(stderr, "Invalid src CIDR: %s\n", src_str);
            return;
        }
        if (inet_pton(AF_INET, dst_str, &other_ip) != 1) {
            fprintf(stderr, "Invalid dst IP: %s\n", dst_str);
            return;
        }
        build_cidr_key(&key, ip, other_ip, prefix, port, (__u8)proto);
    } else if (dst_cidr) {
        if (parse_cidr(dst_str, &ip, &prefix) != 0) {
            fprintf(stderr, "Invalid dst CIDR: %s\n", dst_str);
            return;
        }
        if (inet_pton(AF_INET, src_str, &other_ip) != 1) {
            fprintf(stderr, "Invalid src IP: %s\n", src_str);
            return;
        }
        build_cidr_key(&key, ip, other_ip, prefix, port, (__u8)proto);
    }

    const char *map_path = src_cidr ? PIN_CIDR_SRC_POLICY : PIN_CIDR_DST_POLICY;
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get pinned CIDR map. Please run './update_map start <interface>' first.\n");
        return;
    }

    int err = bpf_map_delete_elem(map_fd, &key);
    if (err) {
        fprintf(stderr, "Failed to delete CIDR rule: %s (error code: %d)\n", strerror(errno), err);
        close(map_fd);
        return;
    }

    printf("CIDR rule deleted: Src=%s Dst=%s Port=%d Proto=%d\n",
           src_str, dst_str, port, proto);
    close(map_fd);
}

void addRule(char *src_str, char *dst_str, int port, int proto, char *action_str) {
    if (is_cidr(src_str) || is_cidr(dst_str)) {
        addCidrRule(src_str, dst_str, port, proto, action_str);
        return;
    }
    struct flow_key key = {0};
    struct flow_value val = {0};

    // 填充Key
    if (inet_pton(AF_INET, src_str, &key.src_ip) != 1) {
        fprintf(stderr, "Invalid src IP: %s\n", src_str);
        return;
    }
    if (inet_pton(AF_INET, dst_str, &key.dst_ip) != 1) {
        fprintf(stderr, "Invalid dst IP: %s\n", dst_str);
        return;
    }
    key.port = htons(port);  // 转换为主机字节序
    key.proto = (__u8)proto;

    // 填充Value
    if (strcmp(action_str, "drop") == 0) {
        val.action = 1;
    } else {
        val.action = 0;
    }
    val.counter = 0;

    // 首先尝试通过固定的map路径访问
    int map_fd = bpf_obj_get(PIN_NET_POLICY);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get pinned map '/sys/fs/bpf/tc_filter_net_policy', trying alternative...\n");
        
        // 尝试通过旧的固定路径
        map_fd = bpf_obj_get("/sys/fs/bpf/net_policy");
        if (map_fd < 0) {
            fprintf(stderr, "Failed to get pinned map '/sys/fs/bpf/net_policy', trying by map ID...\n");
            
            // 尝试通过bpftool获取net_policy map的ID
            FILE *fp;
            char buffer[256];
            int map_id = -1;
            
            // 尝试使用jq (如果可用)
            fp = popen("bpftool map list -j 2>/dev/null | jq -r '.[] | select(.name==\"net_policy\") | .id' 2>/dev/null", "r");
            if (fp) {
                if (fgets(buffer, sizeof(buffer), fp) != NULL) {
                    if (sscanf(buffer, "%d", &map_id) == 1 && map_id > 0) {
                        printf("Found net_policy map ID via jq: %d\n", map_id);
                    }
                }
                pclose(fp);
            }
            
            // 如果jq没找到，尝试直接解析bpftool输出
            if (map_id < 0) {
                fp = popen("bpftool map list 2>/dev/null | grep -A2 'name net_policy' | grep '^[[:space:]]*[0-9]*:' | sed 's/[[:space:]]*\\([0-9]*\\):.*/\\1/'", "r");
                if (fp) {
                    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
                        if (sscanf(buffer, "%d", &map_id) == 1 && map_id > 0) {
                            printf("Found net_policy map ID via grep: %d\n", map_id);
                        }
                    }
                    pclose(fp);
                }
            }
            
            // 如果找到了map ID，尝试通过系统调用获取fd
            if (map_id > 0) {
                #ifdef __NR_bpf
                union bpf_attr attr = {
                    .map_id = map_id,
                };
                
                // 使用bpf syscall通过ID获取map fd
                map_fd = syscall(__NR_bpf, BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
                if (map_fd >= 0) {
                    fprintf(stderr, "Successfully got map_fd %d by ID: %d\n", map_fd, map_id);
                } else {
                    fprintf(stderr, "Failed to get map by ID %d, error: %s (errno=%d)\n", 
                            map_id, strerror(errno), errno);
                    fprintf(stderr, "Note: BPF_MAP_GET_FD_BY_ID may be restricted by kernel security policies.\n");
                    fprintf(stderr, "Try: echo 1 > /proc/sys/kernel/sysctl_bpf_stats_enabled\n");
                }
                #else
                fprintf(stderr, "BPF syscall not available on this system\n");
                #endif
            }
        } else {
            fprintf(stderr, "Successfully got map_fd via pin path: %d\n", map_fd);
        }
    } else {
        fprintf(stderr, "Successfully got map_fd via pinned map: %d\n", map_fd);
    }
    
    // 如果通过ID获取还是失败，尝试最后的备用方法：遍历所有map
    if (map_fd < 0) {
        fprintf(stderr, "Trying alternative method: searching through all available maps...\n");
        
        FILE *fp = popen("bpftool map list 2>/dev/null", "r");
        if (fp) {
            char line[512];
            int current_id = -1;
            while (fgets(line, sizeof(line), fp)) {
                // 解析每行，检查是否是map ID行
                if (sscanf(line, "%d:", &current_id) == 1) {
                    // 读取下一行，检查是否是net_policy
                    if (fgets(line, sizeof(line), fp)) {
                        if (strstr(line, "name net_policy")) {
                            fprintf(stderr, "Found net_policy at ID %d via parsing\n", current_id);
                            
                            // 最后尝试：直接使用bpf_obj_get但带有特殊处理
                            fprintf(stderr, "Cannot directly access map ID %d from this process.\n", current_id);
                            fprintf(stderr, "The map may be in use by another program (tc filter).\n");
                            fprintf(stderr, "To update this map, the map must be pinned to a filesystem path.\n");
                            fprintf(stderr, "Please run './update_map start <interface>' first to pin the map.\n");
                            break;
                        }
                    }
                }
            }
            pclose(fp);
        }
    }

    // 如果找到了已固定的map或通过ID获取的map，直接使用它
    if (map_fd >= 0) {
        // 使用找到的map_fd更新map
        int err = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update existing map: %s (error code: %d)\n", strerror(errno), err);
            close(map_fd);
            return;
        }

        printf("Rule updated in existing map: Src=%s Dst=%s Port=%d Proto=%d Action=%s\n",
               src_str, dst_str, port, proto, action_str);

        close(map_fd);
    } else {
        // 如果没找到已固定的map，尝试通过对象文件加载（传统方式）
        fprintf(stderr, "Failed to find existing map, trying to load from object file...\n");
        
        // 设置libbpf日志级别以减少警告
        libbpf_set_print(NULL);

        // 只加载tc_filter.bpf.o
        struct bpf_object *obj = NULL;
        
        obj = bpf_object__open_file("tc_filter.bpf.o", NULL);
        if (obj) {
            printf("Loaded BPF object from: tc_filter.bpf.o\n");
        } else {
            fprintf(stderr, "Failed to open tc_filter.bpf.o\n");
            return;
        }
        
        if (!obj) {
            fprintf(stderr, "Failed to open any BPF object file\n");
            return;
        }

        // 设置严格模式以提高兼容性
        libbpf_set_strict_mode(LIBBPF_STRICT_NONE);

        int err = bpf_object__load(obj);
        if (err) {
            fprintf(stderr, "Failed to load eBPF object: %d\n", err);
            bpf_object__close(obj);
            return;
        }

        map_fd = bpf_object__find_map_fd_by_name(obj, "net_policy");
        if (map_fd < 0) {
            fprintf(stderr, "Failed to find map 'net_policy': %d\n", map_fd);
            bpf_object__close(obj);
            return;
        }

        // 更新map
        err = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update new map: %s (error code: %d)\n", strerror(errno), err);
            close(map_fd);
            bpf_object__close(obj);
            return;
        }

        printf("Rule updated in new map: Src=%s Dst=%s Port=%d Proto=%d Action=%s\n",
               src_str, dst_str, port, proto, action_str);

        close(map_fd);
        bpf_object__close(obj);
    }
}

static int append_entry(char **result, size_t *result_len, int *count, const char *entry) {
    size_t entry_len = strlen(entry);
    size_t new_len = *result_len + entry_len + (*count > 0 ? 1 : 0) + 1;
    char *new_result = realloc(*result, new_len);
    if (!new_result) {
        return -1;
    }
    *result = new_result;
    if (*count > 0) {
        strcat(*result, "\n");
    }
    strcat(*result, entry);
    *result_len = new_len - 1;
    (*count)++;
    return 0;
}

static void queryCidrMap(const char *map_path, int is_src, char **result, size_t *result_len, int *count) {
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        return;
    }

    struct cidr_key key = {0};
    struct cidr_key next_key = {0};
    struct flow_value val = {0};
    bool first_key = true;
    while (bpf_map_get_next_key(map_fd, first_key ? NULL : &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
            char ip_str[INET_ADDRSTRLEN];
            char other_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &next_key.ip, ip_str, sizeof(ip_str));
            inet_ntop(AF_INET, &next_key.other_ip, other_ip_str, sizeof(other_ip_str));

            int cidr_prefix = 0;
            if (next_key.prefixlen <= 32) {
                cidr_prefix = (int)next_key.prefixlen;
            } else {
                cidr_prefix = (int)next_key.prefixlen - CIDR_REST_BITS;
            }
            if (cidr_prefix < 0) {
                cidr_prefix = 0;
            }
            if (cidr_prefix > 32) {
                cidr_prefix = 32;
            }

            const char *action_desc = (val.action == 1) ? "drop" : "accept";
            char entry[256];
            snprintf(entry, sizeof(entry), "%s %s/%d %s %d %d %s %llu",
                     is_src ? "cidr-src" : "cidr-dst",
                     ip_str,
                     cidr_prefix,
                     other_ip_str,
                     ntohs(next_key.port),
                     next_key.proto,
                     action_desc,
                     (unsigned long long)val.counter);

            if (append_entry(result, result_len, count, entry) != 0) {
                close(map_fd);
                return;
            }
        }

        first_key = false;
        memcpy(&key, &next_key, sizeof(key));
    }

    close(map_fd);
}

/*
 * 查询并返回当前 eBPF map 中的所有规则。
 */
char* queryRules() {
    int map_fd = -1;
    struct flow_key key = {0};
    struct flow_key next_key = {0};
    struct flow_value val = {0};
    int count = 0;

    // 首先尝试通过固定的map路径访问
    map_fd = bpf_obj_get(PIN_NET_POLICY);
    if (map_fd < 0) {
        // 尝试通过旧的固定路径
        map_fd = bpf_obj_get("/sys/fs/bpf/net_policy");
        if (map_fd < 0) {
            fprintf(stderr, "Failed to get pinned map. Please run './update_map start <interface>' first.\n");
            return NULL;
        }
    }

    char *result = malloc(1);
    if (!result) {
        close(map_fd);
        return NULL;
    }
    result[0] = '\0';
    size_t result_len = 0;

    bool first_key = true;
    while (bpf_map_get_next_key(map_fd, first_key ? NULL : &key, &next_key) == 0) {
        // 获取当前 key 对应的 value
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
            // 格式化 IP 地址
            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
            
            inet_ntop(AF_INET, &next_key.src_ip, src_ip_str, sizeof(src_ip_str));
            inet_ntop(AF_INET, &next_key.dst_ip, dst_ip_str, sizeof(dst_ip_str));

            // 确定动作描述
            const char *action_desc = (val.action == 1) ? "drop" : "accept";

            char entry[256];
            snprintf(entry, sizeof(entry), "%s %s %d %d %s %llu",
                     src_ip_str,
                     dst_ip_str,
                     ntohs(next_key.port),
                     next_key.proto,
                     action_desc,
                     (unsigned long long)val.counter);

            if (append_entry(&result, &result_len, &count, entry) != 0) {
                free(result);
                close(map_fd);
                return NULL;
            }
        }

        first_key = false;

        // 将 next_key 复制给 key，准备获取下一个 key
        memcpy(&key, &next_key, sizeof(key));
    }

    close(map_fd);

    // 追加 CIDR 规则
    queryCidrMap(PIN_CIDR_SRC_POLICY, 1, &result, &result_len, &count);
    queryCidrMap(PIN_CIDR_DST_POLICY, 0, &result, &result_len, &count);

    if (count == 0) {
        free(result);
        return NULL;
    }

    return result;
}

/*
 * 从 eBPF map 中删除一条规则。
 */
void deleteRule(char *src_str, char *dst_str, int port, int proto) {
    if (is_cidr(src_str) || is_cidr(dst_str)) {
        deleteCidrRule(src_str, dst_str, port, proto);
        return;
    }
    struct flow_key key = {0};

    if (inet_pton(AF_INET, src_str, &key.src_ip) != 1) {
        fprintf(stderr, "Invalid src IP: %s\n", src_str);
        return;
    }
    if (inet_pton(AF_INET, dst_str, &key.dst_ip) != 1) {
        fprintf(stderr, "Invalid dst IP: %s\n", dst_str);
        return;
    }
    key.port = htons(port);
    key.proto = (__u8)proto;

    int map_fd = bpf_obj_get(PIN_NET_POLICY);
    if (map_fd < 0) {
        map_fd = bpf_obj_get("/sys/fs/bpf/net_policy");
        if (map_fd < 0) {
            fprintf(stderr, "Failed to get pinned map. Please run './update_map start <interface>' first.\n");
            return;
        }
    }

    int err = bpf_map_delete_elem(map_fd, &key);
    if (err) {
        fprintf(stderr, "Failed to delete rule: %s (error code: %d)\n", strerror(errno), err);
        close(map_fd);
        return;
    }

    printf("Rule deleted: Src=%s Dst=%s Port=%d Proto=%d\n", src_str, dst_str, port, proto);
    close(map_fd);
}

/*
 * 解析白名单方向掩码（ingress/egress/both/数字）。
 */
static int parse_mode_mask(const char *mask_str) {
    if (!mask_str) {
        return 0;
    }
    if (strcmp(mask_str, "ingress") == 0) {
        return MODE_INGRESS;
    }
    if (strcmp(mask_str, "egress") == 0) {
        return MODE_EGRESS;
    }
    if (strcmp(mask_str, "both") == 0) {
        return MODE_INGRESS | MODE_EGRESS;
    }
    // 尝试解析为数字
    int mask = atoi(mask_str);
    return mask;
}

/*
 * 为指定 Pod IP 设置白名单管控方向。
 */
static void setPolicyMode(char *ip_str, const char *mask_str) {
    __u32 ip = 0;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        fprintf(stderr, "Invalid IP: %s\n", ip_str);
        return;
    }

    int map_fd = bpf_obj_get(PIN_POLICY_MODE);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get pinned policy mode map. Please run './update_map start <interface>' first.\n");
        return;
    }

    __u8 mask = (__u8)parse_mode_mask(mask_str);
    if (mask == 0) {
        fprintf(stderr, "Invalid mode mask: %s\n", mask_str ? mask_str : "(null)");
        close(map_fd);
        return;
    }

    int err = bpf_map_update_elem(map_fd, &ip, &mask, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to set policy mode: %s (error code: %d)\n", strerror(errno), err);
        close(map_fd);
        return;
    }

    printf("Policy mode set: IP=%s Mask=%u\n", ip_str, mask);
    close(map_fd);
}

/*
 * 清理指定 Pod IP 的白名单管控方向。
 */
static void clearPolicyMode(char *ip_str) {
    __u32 ip = 0;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        fprintf(stderr, "Invalid IP: %s\n", ip_str);
        return;
    }

    int map_fd = bpf_obj_get(PIN_POLICY_MODE);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get pinned policy mode map. Please run './update_map start <interface>' first.\n");
        return;
    }

    int err = bpf_map_delete_elem(map_fd, &ip);
    if (err) {
        fprintf(stderr, "Failed to clear policy mode: %s (error code: %d)\n", strerror(errno), err);
        close(map_fd);
        return;
    }

    printf("Policy mode cleared: IP=%s\n", ip_str);
    close(map_fd);
}

/*
 * 通过接口名获取 ifindex。
 */
static int get_ifindex(const char *iface) {
    if (!iface) {
        return 0;
    }
    return if_nametoindex(iface);
}

/*
 * 获取 endpoint_rules 外层 map fd。
 */
static int get_endpoint_rules_fd() {
    int map_fd = bpf_obj_get(PIN_ENDPOINT_RULES);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get pinned endpoint rules map. Please run './update_map start <interface>' first.\n");
    }
    return map_fd;
}

/*
 * 为指定接口创建 endpoint 级 inner map，并绑定到外层 map。
 */
static void addEndpoint(const char *iface) {
    int ifindex = get_ifindex(iface);
    if (ifindex <= 0) {
        fprintf(stderr, "Invalid interface: %s\n", iface ? iface : "(null)");
        return;
    }

    int outer_fd = get_endpoint_rules_fd();
    if (outer_fd < 0) {
        return;
    }

    struct bpf_map_create_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);

    int inner_fd = bpf_map_create(BPF_MAP_TYPE_HASH,
                                  "endpoint_rules_inner",
                                  sizeof(struct flow_key),
                                  sizeof(struct flow_value),
                                  1024,
                                  &opts);
    if (inner_fd < 0) {
        fprintf(stderr, "Failed to create inner map for iface %s: %s\n", iface, strerror(errno));
        close(outer_fd);
        return;
    }

    if (bpf_map_update_elem(outer_fd, &ifindex, &inner_fd, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to bind endpoint map for iface %s: %s\n", iface, strerror(errno));
        close(inner_fd);
        close(outer_fd);
        return;
    }

    printf("Endpoint map bound: iface=%s ifindex=%d\n", iface, ifindex);
    close(inner_fd);
    close(outer_fd);
}

/*
 * 解绑指定接口的 endpoint map。
 */
static void delEndpoint(const char *iface) {
    int ifindex = get_ifindex(iface);
    if (ifindex <= 0) {
        fprintf(stderr, "Invalid interface: %s\n", iface ? iface : "(null)");
        return;
    }

    int outer_fd = get_endpoint_rules_fd();
    if (outer_fd < 0) {
        return;
    }

    if (bpf_map_delete_elem(outer_fd, &ifindex) != 0) {
        fprintf(stderr, "Failed to unbind endpoint map for iface %s: %s\n", iface, strerror(errno));
        close(outer_fd);
        return;
    }

    printf("Endpoint map unbound: iface=%s ifindex=%d\n", iface, ifindex);
    close(outer_fd);
}

/*
 * 在 endpoint inner map 中添加规则。
 */
static void addEndpointRule(const char *iface, char *src_str, char *dst_str, int port, int proto, char *action_str) {
    int ifindex = get_ifindex(iface);
    if (ifindex <= 0) {
        fprintf(stderr, "Invalid interface: %s\n", iface ? iface : "(null)");
        return;
    }

    int outer_fd = get_endpoint_rules_fd();
    if (outer_fd < 0) {
        return;
    }

    int inner_fd = -1;
    if (bpf_map_lookup_elem(outer_fd, &ifindex, &inner_fd) != 0 || inner_fd < 0) {
        fprintf(stderr, "Endpoint map not found for iface %s, run 'endpoint add' first.\n", iface);
        close(outer_fd);
        return;
    }

    struct flow_key key = {0};
    struct flow_value val = {0};

    if (inet_pton(AF_INET, src_str, &key.src_ip) != 1) {
        fprintf(stderr, "Invalid src IP: %s\n", src_str);
        close(inner_fd);
        close(outer_fd);
        return;
    }
    if (inet_pton(AF_INET, dst_str, &key.dst_ip) != 1) {
        fprintf(stderr, "Invalid dst IP: %s\n", dst_str);
        close(inner_fd);
        close(outer_fd);
        return;
    }
    key.port = htons(port);
    key.proto = (__u8)proto;

    val.action = (strcmp(action_str, "drop") == 0) ? 1 : 0;
    val.counter = 0;

    if (bpf_map_update_elem(inner_fd, &key, &val, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update endpoint rule: %s\n", strerror(errno));
    } else {
        printf("Endpoint rule updated: iface=%s Src=%s Dst=%s Port=%d Proto=%d Action=%s\n",
               iface, src_str, dst_str, port, proto, action_str);
    }

    close(inner_fd);
    close(outer_fd);
}

/*
 * 在 endpoint inner map 中删除规则。
 */
static void delEndpointRule(const char *iface, char *src_str, char *dst_str, int port, int proto) {
    int ifindex = get_ifindex(iface);
    if (ifindex <= 0) {
        fprintf(stderr, "Invalid interface: %s\n", iface ? iface : "(null)");
        return;
    }

    int outer_fd = get_endpoint_rules_fd();
    if (outer_fd < 0) {
        return;
    }

    int inner_fd = -1;
    if (bpf_map_lookup_elem(outer_fd, &ifindex, &inner_fd) != 0 || inner_fd < 0) {
        fprintf(stderr, "Endpoint map not found for iface %s, run 'endpoint add' first.\n", iface);
        close(outer_fd);
        return;
    }

    struct flow_key key = {0};
    if (inet_pton(AF_INET, src_str, &key.src_ip) != 1) {
        fprintf(stderr, "Invalid src IP: %s\n", src_str);
        close(inner_fd);
        close(outer_fd);
        return;
    }
    if (inet_pton(AF_INET, dst_str, &key.dst_ip) != 1) {
        fprintf(stderr, "Invalid dst IP: %s\n", dst_str);
        close(inner_fd);
        close(outer_fd);
        return;
    }
    key.port = htons(port);
    key.proto = (__u8)proto;

    if (bpf_map_delete_elem(inner_fd, &key) != 0) {
        fprintf(stderr, "Failed to delete endpoint rule: %s\n", strerror(errno));
    } else {
        printf("Endpoint rule deleted: iface=%s Src=%s Dst=%s Port=%d Proto=%d\n",
               iface, src_str, dst_str, port, proto);
    }

    close(inner_fd);
    close(outer_fd);
}

/*
 * 命令行入口：start/add/delete/query。
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s start <interface_name> | %s add <src_ip|src_cidr> <dst_ip|dst_cidr> <port> <proto> <action> | %s delete <src_ip|src_cidr> <dst_ip|dst_cidr> <port> <proto> | %s query | %s mode set <ip> <ingress|egress|both|mask> | %s mode del <ip> | %s endpoint add <iface> | %s endpoint del <iface> | %s endpoint add-rule <iface> <src_ip> <dst_ip> <port> <proto> <action> | %s endpoint del-rule <iface> <src_ip> <dst_ip> <port> <proto>\n",
                argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "start") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s start <interface_name>\n", argv[0]);
            return 1;
        }
        startEBPF(argv[2]);
    } else if (strcmp(argv[1], "add") == 0) {
        if (argc != 7) {
            fprintf(stderr, "Usage: %s add <src_ip> <dst_ip> <port> <proto> <action>\n", argv[0]);
            return 1;
        }
        addRule(argv[2], argv[3], atoi(argv[4]), atoi(argv[5]), argv[6]);
    } else if (strcmp(argv[1], "query") == 0) {
        char *result = queryRules();
        if (result) {
            printf("%s\n", result);
            free(result);
        } else {
            printf("Map is empty or query failed.\n");
        }
    } else if (strcmp(argv[1], "delete") == 0) {
        if (argc != 6) {
            fprintf(stderr, "Usage: %s delete <src_ip> <dst_ip> <port> <proto>\n", argv[0]);
            return 1;
        }
        deleteRule(argv[2], argv[3], atoi(argv[4]), atoi(argv[5]));
    } else if (strcmp(argv[1], "mode") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s mode set <ip> <ingress|egress|both|mask> | %s mode del <ip>\n", argv[0], argv[0]);
            return 1;
        }
        if (strcmp(argv[2], "set") == 0) {
            if (argc != 5) {
                fprintf(stderr, "Usage: %s mode set <ip> <ingress|egress|both|mask>\n", argv[0]);
                return 1;
            }
            setPolicyMode(argv[3], argv[4]);
        } else if (strcmp(argv[2], "del") == 0) {
            if (argc != 4) {
                fprintf(stderr, "Usage: %s mode del <ip>\n", argv[0]);
                return 1;
            }
            clearPolicyMode(argv[3]);
        } else {
            fprintf(stderr, "Unknown mode command: %s. Use 'set' or 'del'.\n", argv[2]);
            return 1;
        }
    } else if (strcmp(argv[1], "endpoint") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s endpoint add <iface> | %s endpoint del <iface> | %s endpoint add-rule <iface> <src_ip> <dst_ip> <port> <proto> <action> | %s endpoint del-rule <iface> <src_ip> <dst_ip> <port> <proto>\n",
                    argv[0], argv[0], argv[0], argv[0]);
            return 1;
        }

        if (strcmp(argv[2], "add") == 0) {
            if (argc != 4) {
                fprintf(stderr, "Usage: %s endpoint add <iface>\n", argv[0]);
                return 1;
            }
            addEndpoint(argv[3]);
        } else if (strcmp(argv[2], "del") == 0) {
            if (argc != 4) {
                fprintf(stderr, "Usage: %s endpoint del <iface>\n", argv[0]);
                return 1;
            }
            delEndpoint(argv[3]);
        } else if (strcmp(argv[2], "add-rule") == 0) {
            if (argc != 9) {
                fprintf(stderr, "Usage: %s endpoint add-rule <iface> <src_ip> <dst_ip> <port> <proto> <action>\n", argv[0]);
                return 1;
            }
            addEndpointRule(argv[3], argv[4], argv[5], atoi(argv[6]), atoi(argv[7]), argv[8]);
        } else if (strcmp(argv[2], "del-rule") == 0) {
            if (argc != 8) {
                fprintf(stderr, "Usage: %s endpoint del-rule <iface> <src_ip> <dst_ip> <port> <proto>\n", argv[0]);
                return 1;
            }
            delEndpointRule(argv[3], argv[4], argv[5], atoi(argv[6]), atoi(argv[7]));
        } else {
            fprintf(stderr, "Unknown endpoint command: %s. Use 'add', 'del', 'add-rule', or 'del-rule'.\n", argv[2]);
            return 1;
        }
    } else {
        fprintf(stderr, "Unknown command: %s. Use 'start', 'add', 'delete', 'query', 'mode', or 'endpoint'.\n", argv[1]);
        return 1;
    }

    return 0;
}
