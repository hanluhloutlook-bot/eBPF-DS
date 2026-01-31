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

// 白名单方向位
#define MODE_INGRESS 1
#define MODE_EGRESS  2

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

    // 如果是 TCP/UDP，提取端口
    if (ip->protocol == 6 || ip->protocol == 17) {
        // 关键修正：显式定义 L4 偏移。
        // 在 4.19 验证器眼中，必须先做加法，再做 boundary 检查，最后才能解引用。
        __u32 l4_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
        
        // 检查源端口和目的端口（共 4 字节）是否都在范围内
        if (data + l4_offset + 4 <= data_end) {
            // 直接计算目的端口的地址（源端口占 2 字节，目的端口在偏移 2 字节处）
            __u16 *dport = (__u16 *)(data + l4_offset + 2);
            key.port = *dport; 
        }
    }

    // 5. 优先查 endpoint 级规则（按 ifindex 找 inner map）
    __u32 ifindex = skb->ifindex;
    void *inner_map = bpf_map_lookup_elem(&endpoint_rules, &ifindex);
    struct flow_value *val = NULL;
    if (inner_map) {
        val = bpf_map_lookup_elem(inner_map, &key);
    }

    // 6. 若 endpoint 级规则未命中，则回退共享规则
    if (!val) {
        val = bpf_map_lookup_elem(&net_policy, &key);
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

        // 命中 allow 规则，直接放行
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