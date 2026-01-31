#ifndef __POLICY_H__
#define __POLICY_H__

// 这里的类型定义要与 vmlinux.h 或标准头文件兼容
typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct flow_key {
    __u32 src_ip;   // 源 IP (网络字节序)
    __u32 dst_ip;   // 目的 IP (网络字节序)
    __u32 port;     // 目的端口 (本地/主机字节序，方便解析)
    __u8  proto;    // 协议 (IPPROTO_TCP / IPPROTO_UDP)
    __u8  pad[3];   // 【重要】手动填充，确保结构体大小是 4 的倍数，防止编译器自动填充导致 Key 不匹配
};

struct flow_value {
    __u32 action;   // 0 = ALLOW (TC_ACT_OK), 1 = DROP (TC_ACT_SHOT)
    __u64 counter;  // 命中统计
};

#endif