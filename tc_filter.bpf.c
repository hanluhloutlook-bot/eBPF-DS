#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h> // 必须包含 TC 动作常量
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "policy.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(struct flow_value));
} net_policy SEC(".maps");

// endpoint 级规则：外层 map（key=ifindex, value=inner map fd）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(struct flow_value));
} endpoint_rules_inner SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __array(values, endpoint_rules_inner);
} endpoint_rules SEC(".maps");

// 目标 Pod 的白名单管控模式：按 IP 记录需要强制白名单的方向
// key: Pod IP（网络字节序） value: bitmask(1=ingress, 2=egress)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
} policy_mode SEC(".maps");

// CIDR 规则（src/dst）
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(key_size, sizeof(struct cidr_key));
    __uint(value_size, sizeof(struct flow_value));
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cidr_src_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(key_size, sizeof(struct cidr_key));
    __uint(value_size, sizeof(struct flow_value));
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cidr_dst_policy SEC(".maps");

// 连接跟踪（用于回包放行）
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __uint(key_size, sizeof(struct ct_key));
    __uint(value_size, sizeof(__u64)); // 时间戳（ns）
} conntrack_map SEC(".maps");

// 连接跟踪 TTL 配置（默认 60s）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct ct_ttl_value));
} conntrack_ttl SEC(".maps");

// 白名单方向位
#define MODE_INGRESS 1
#define MODE_EGRESS  2

// 连接跟踪超时默认值（ns）
#define CT_TIMEOUT_DEFAULT_NS (60ULL * 1000000000ULL)

/*
 * tc 入口程序：解析报文并根据 map 规则执行放行/丢弃。
 */
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    // 1. 获取以太网帧头
    struct ethhdr *eth = data;
    // 边界检查：确保不会访问越界
    if ((void *)(eth + 1) > data_end) return 0;
    // 2. 判断是否为 IP 数据包 (0x0800)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return 0;
    // 3. 获取 IP 头,边界检查：确保 IP 头完整
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return 0;

    // 4. 构造 Key
    struct flow_key key;
    __builtin_memset(&key, 0, sizeof(key)); // 4.19 必须显式清零，否则报错
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.port   = 0;
    key.proto  = ip->protocol;
    __u16 sport = 0;
    __u16 dport = 0;

    // 如果是 TCP/UDP，提取端口
    if (ip->protocol == 6 || ip->protocol == 17) {
        // 关键修正：显式定义 L4 偏移。
        // 在 4.19 验证器眼中，必须先做加法，再做 boundary 检查，最后才能解引用。
        __u32 l4_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
        
        // 检查源端口和目的端口（共 4 字节）是否都在范围内
        if (data + l4_offset + 4 <= data_end) {
            // 直接读取源/目的端口
            __u16 *ports = (__u16 *)(data + l4_offset);
            sport = ports[0];
            dport = ports[1];
            key.port = dport;
        }
    }

    // 4.5 连接跟踪回包放行（优先级高于策略）
    if (ip->protocol == 6 || ip->protocol == 17 || ip->protocol == 1) {
        struct ct_key cur = {};
        cur.src_ip = ip->saddr;
        cur.dst_ip = ip->daddr;
        cur.src_port = sport;
        cur.dst_port = dport;
        cur.proto = ip->protocol;
        __u64 *last_seen = bpf_map_lookup_elem(&conntrack_map, &cur);
        if (last_seen) {
            __u64 now = bpf_ktime_get_ns();
            __u64 ttl_ns = CT_TIMEOUT_DEFAULT_NS;
            __u32 ttl_key = 0;
            struct ct_ttl_value *ttl_val = bpf_map_lookup_elem(&conntrack_ttl, &ttl_key);
            if (ttl_val && ttl_val->timeout_ns > 0) {
                ttl_ns = ttl_val->timeout_ns;
            }
            if (now - *last_seen <= ttl_ns) {
                *last_seen = now;
                return 0; // 回包放行
            }
        }
    }

    // 5. 优先查 endpoint 级规则（按 ifindex 找 inner map）
    __u32 ifindex = skb->ifindex;
    void *inner_map = bpf_map_lookup_elem(&endpoint_rules, &ifindex);
    struct flow_value *val = NULL;
    if (inner_map) {
        val = bpf_map_lookup_elem(inner_map, &key);
        if (!val && key.port != 0) {
            struct flow_key any_key = key;
            any_key.port = 0;
            val = bpf_map_lookup_elem(inner_map, &any_key);
        }
    }

    // 6. 若 endpoint 级规则未命中，则回退共享规则
    if (!val) {
        val = bpf_map_lookup_elem(&net_policy, &key);
        if (!val && key.port != 0) {
            struct flow_key any_key = key;
            any_key.port = 0;
            val = bpf_map_lookup_elem(&net_policy, &any_key);
        }
    }
    if (val) {
        // 命中规则，原子更新计数器
        __sync_fetch_and_add(&val->counter, 1);
        // 执行动作: 1 为 Drop, 0 为 Allow
        if (val->action == 1){
            static const char fmt[] = "Drop packet: Src=%x Dst=%x\n";
            bpf_trace_printk(fmt, sizeof(fmt), ip->saddr, ip->daddr);
            return 2; // TC_ACT_SHOT
        }

        // 命中 allow 规则，写入连接跟踪（回包放行）
        if (ip->protocol == 6 || ip->protocol == 17 || ip->protocol == 1) {
            struct ct_key rev = {};
            rev.src_ip = ip->daddr;
            rev.dst_ip = ip->saddr;
            rev.src_port = dport;
            rev.dst_port = sport;
            rev.proto = ip->protocol;
            __u64 now = bpf_ktime_get_ns();
            bpf_map_update_elem(&conntrack_map, &rev, &now, BPF_ANY);
        }

        // 命中 allow 规则，直接放行
        return 0; // TC_ACT_OK
    }

    // 6.5 CIDR 规则匹配（src/dst）
    struct cidr_key ckey = {};
    ckey.prefixlen = 112; // 32(src/dst) + 32(other) + 16(port) + 8(proto) + 24(pad)
    ckey.ip = ip->saddr;
    ckey.other_ip = ip->daddr;
    ckey.port = key.port;
    ckey.proto = key.proto;
    val = bpf_map_lookup_elem(&cidr_src_policy, &ckey);
    if (!val) {
        ckey.ip = ip->daddr;
        ckey.other_ip = ip->saddr;
        val = bpf_map_lookup_elem(&cidr_dst_policy, &ckey);
    }
    if (!val && key.port != 0) {
        ckey.ip = ip->saddr;
        ckey.other_ip = ip->daddr;
        ckey.port = 0;
        val = bpf_map_lookup_elem(&cidr_src_policy, &ckey);
        if (!val) {
            ckey.ip = ip->daddr;
            ckey.other_ip = ip->saddr;
            val = bpf_map_lookup_elem(&cidr_dst_policy, &ckey);
        }
    }
    if (val) {
        __sync_fetch_and_add(&val->counter, 1);
        if (val->action == 1) {
            return 2; // TC_ACT_SHOT
        }
        if (ip->protocol == 6 || ip->protocol == 17 || ip->protocol == 1) {
            struct ct_key rev = {};
            rev.src_ip = ip->daddr;
            rev.dst_ip = ip->saddr;
            rev.src_port = dport;
            rev.dst_port = sport;
            rev.proto = ip->protocol;
            __u64 now = bpf_ktime_get_ns();
            bpf_map_update_elem(&conntrack_map, &rev, &now, BPF_ANY);
        }
        return 0; // TC_ACT_OK
    }

    // 7. 未命中规则时，如果源/目的在白名单管控模式，则默认拒绝
    // 注意：同一条 Pod 出向流量可能在宿主机侧表现为 ingress，故同时检查 src/egress 与 dst/ingress。
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    __u8 *dst_mode = bpf_map_lookup_elem(&policy_mode, &dst_ip);
    if (dst_mode && ((*dst_mode) & MODE_INGRESS)) {
        return 2; // TC_ACT_SHOT
    }

    __u8 *src_mode = bpf_map_lookup_elem(&policy_mode, &src_ip);
    if (src_mode && ((*src_mode) & MODE_EGRESS)) {
        return 2; // TC_ACT_SHOT
    }

    return 0; // TC_ACT_OK
}

char _license[] SEC("license") = "GPL";