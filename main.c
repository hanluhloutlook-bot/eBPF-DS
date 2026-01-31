#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include "policy.h"

/*
 * 提升进程的内存锁定上限，避免 eBPF 加载失败。
 */
void bump_memlock() {
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
        fprintf(stderr, "警告: 无法提升 RLIMIT_MEMLOCK 限制\n");
    } 
}

// 处理解析并更新 Map 的逻辑
/*
 * 处理单个 HTTP 请求并更新 eBPF map。
 */
void handle_http_request(int client_sock, int map_fd) {
    char buffer[1024];
    read(client_sock, buffer, sizeof(buffer) - 1);

    // 简单的解析逻辑：查找 GET /add?...
    if (strstr(buffer, "GET /add")) {
        struct flow_key key;
        struct flow_value value;
        memset(&key, 0, sizeof(key));     // 4.19 必须显式清零
        memset(&value, 0, sizeof(value));

        char src_str[16] = {0}, dst_str[16] = {0};
        int port = 0, proto = 6, action = 1; // 默认 TCP (6), 默认 Drop (1)

        // 解析参数 (实际生产环境建议使用更严谨的解析器)
        sscanf(strstr(buffer, "src="), "src=%[^&]", src_str);
        sscanf(strstr(buffer, "dst="), "dst=%[^&]", dst_str);
        if (strstr(buffer, "port=")) sscanf(strstr(buffer, "port="), "port=%d", &port);
        if (strstr(buffer, "proto=")) sscanf(strstr(buffer, "proto="), "proto=%d", &proto);
        if (strstr(buffer, "action=")) {
            char act_str[10];
            sscanf(strstr(buffer, "action="), "action=%[^& ]", act_str);
            action = (strcmp(act_str, "drop") == 0) ? 1 : 0;
        }

        key.src_ip = inet_addr(src_str);
        key.dst_ip = inet_addr(dst_str);
        key.port = htons((unsigned short)port);
        key.proto = (unsigned char)proto;
        value.action = action;
        value.counter = 0;

        // 更新 eBPF Map
        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) == 0) {
            char resp[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nRule Added Successfully\n";
            send(client_sock, resp, strlen(resp), 0);
            printf("Map Updated: Src=%s, Dst=%s, Port=%d, Action=%d\n", src_str, dst_str, port, action);
        } else {
            char resp[] = "HTTP/1.1 500 Internal Server Error\r\n\r\nFailed to Update Map\n";
            send(client_sock, resp, strlen(resp), 0);
            fprintf(stderr, "Map update failed: %s\n", strerror(errno));
        }
    } else {
        char resp[] = "HTTP/1.1 404 Not Found\r\n\r\nUse /add?src=...&dst=...&port=...\n";
        send(client_sock, resp, strlen(resp), 0);
    }
    close(client_sock);
}

// 运行简单的 HTTP 服务器
/*
 * 启动简易 HTTP 服务器，监听规则更新请求。
 */
void run_http_server(int map_fd) {
    int server_fd, client_sock;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) return;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        return;
    }
    listen(server_fd, 3);
    printf("HTTP Server 正在运行，监听端口 8081...\n");

    while (1) {
        if ((client_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) break;
        handle_http_request(client_sock, map_fd);
    }
}

/*
 * 程序入口：加载 eBPF，挂载 tc，并启动 HTTP 服务。
 */
int main() {
    bump_memlock();

    struct bpf_object *obj;
    int err, map_fd;

    // 禁用 libbpf 1.0 严格模式以增强 4.19 兼容性
    libbpf_set_strict_mode(LIBBPF_STRICT_NONE);
    // 尝试使用 bpf_object_open_opts 结构，禁用 BTF 检查
    struct bpf_object_open_opts opts = { .sz = sizeof(opts) };
    
    obj = bpf_object__open_file("tc_filter.bpf.o", &opts);
    if (libbpf_get_error(obj)) return 1;

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Load failed: %d (Check dmesg for BTF/Verifier error)\n", err);
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "net_policy");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map 'net_policy' fd\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("Successfully loaded! Map FD: %d\n", map_fd);

    const char *ifname = "ens33"; // 请修改为你的网卡名
    // 1. 定义固定路径 (BPF FS 通常挂载在 /sys/fs/bpf)
    const char *pin_path = "/sys/fs/bpf/my_tc_prog";
    printf("自动在当前主机上为接口 '%s' 挂载 tc 规则\n", ifname);

    // 2. 清理旧的固定点和 tc 规则 
    unlink(pin_path);
    char cmd[512];
    // 尝试清理旧的 clsact（忽略错误）
    snprintf(cmd, sizeof(cmd), "sudo tc qdisc del dev %s clsact 2>/dev/null", ifname);
    system(cmd);

    // 3. 将加载好的程序固定到文件系统
    struct bpf_program *prog = bpf_object__find_program_by_title(obj, "classifier");
    int prog_fd = bpf_program__fd(prog);
    if (bpf_obj_pin(prog_fd, pin_path) != 0) {
        fprintf(stderr, "无法固定 BPF 程序到 %s", pin_path);
        return 1;
    }

    // 2. 创建 clsact 队列 (这是 Ingress 和 Egress 过滤器的父节点) 
    snprintf(cmd, sizeof(cmd), "sudo tc qdisc add dev %s clsact", ifname);
    printf("RUN: %s\n", cmd); 
    if (system(cmd) != 0) {
        fprintf(stderr, "创建 clsact 失败，请检查网卡名称或权限\n");
        // 如果是因为已存在，通常可以继续，但这里建议检查返回值
    }

    // 4. 让 tc 挂载这个固定好的程序
    // 使用 'object-pinned' 关键字，这是旧版 tc 识别已加载程序的标准方式
    snprintf(cmd, sizeof(cmd), "sudo tc filter add dev %s ingress bpf object-pinned %s da", ifname, pin_path);
    printf("执行挂载: %s\n", cmd);
    if (system(cmd) != 0) {
        fprintf(stderr, "tc 挂载失败\n");
    } else {
        printf("成功挂载！\n");
    }

    // 运行 HTTP 服务器处理 Map 更新
    run_http_server(map_fd);

    bpf_object__close(obj);
    
    return 0;
}