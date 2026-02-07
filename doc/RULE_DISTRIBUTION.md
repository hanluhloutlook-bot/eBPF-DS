# 规则下发与同步机制说明

## 1. 目标
- 保证每个节点只下发“本节点相关 Pod”的规则，避免冗余。
- 支持白名单模式（未命中规则默认拒绝）。
- 支持 endpoint 级规则（与 Cilium 设计对齐）。

## 2. 核心数据结构
### 2.1 eBPF Map
- `endpoint_rules`（Hash-of-Maps）：
  - **key**：`ifindex`（网卡接口索引，唯一标识 endpoint/veth）。
  - **value**：inner map fd（每个 endpoint 的独立规则表）。
- `net_policy`（Hash）：
  - **key**：`flow_key`（src_ip, dst_ip, port, proto）。
  - **value**：`flow_value`（action, counter）。
  - **用途**：共享规则兜底。
- `policy_mode`（Hash）：
  - **key**：Pod IP（网络字节序）。
  - **value**：方向掩码（1=ingress, 2=egress）。
  - **用途**：白名单“未命中默认拒绝”。
- `conntrack_map`（LRU Hash）：
  - **key**：五元组（src_ip, dst_ip, src_port, dst_port, proto）。
  - **value**：最近命中时间戳（ns）。
  - **用途**：回包放行（stateful）。
- `conntrack_ttl`（Array）：
  - **key**：固定 0。
  - **value**：TTL 超时时间（ns）。
  - **用途**：控制回包放行窗口（默认 60s）。

### 2.2 Java 侧缓存
- `POLICY_CACHE`：缓存全量策略请求。
- `lastAppliedRules`：本节点已下发规则集合。
- `lastAppliedModes`：本节点已设置白名单方向集合。

## 3. 规则下发流程
### 3.1 控制面（管理端 -> 控制器）
1. 管理端调用 `/api/networkpolicy/create` 或 `/delete`。
2. 控制器把策略写入 `POLICY_CACHE`（全量缓存）。

### 3.2 节点定时对齐（Reconcile）
1. 定时任务读取 `POLICY_CACHE`。
2. 调用 K8s API 获取本节点 Pod IP 列表（`NODE_NAME`）。
3. 仅保留与本节点 Pod 相关的规则。
4. 生成期望规则集合 + 期望白名单方向集合。
5. 与 `lastAppliedRules` 做 diff：
   - **新增**：调用 `update_map add` 写入规则。
   - **删除**：调用 `update_map delete` 移除规则。
6. 与 `lastAppliedModes` 做 diff：
   - **新增**：调用 `update_map mode set`。
   - **删除**：调用 `update_map mode del`。

### 3.3 eBPF 数据面匹配
1. 进入 tc 程序 `tc_ingress`。
2. **优先**按 `ifindex` 查询 `endpoint_rules` inner map。
3. 若未命中，回退查询 `net_policy`。
3.1 若命中 allow 规则，写入 `conntrack_map` 以放行回包。
4. 若仍未命中：
   - 若 `policy_mode` 标记了该方向白名单 -> **默认拒绝**。
   - 否则默认放行。
4.1 回包命中 `conntrack_map` 且未过期时直接放行。

## 4. 规则生效的关键点
- **endpoint 级规则优先**，保证 Pod 粒度隔离。
- **共享规则兜底**，避免规则下发未覆盖时的空洞。
- **白名单模式**通过 `policy_mode` 实现“未命中即拒绝”。

## 5. Pod 漂移场景如何保证同步
- Pod 漂移后：
  - 新节点下一次定时对齐会感知该 Pod IP，生成规则并下发。
  - 旧节点对齐时发现该 Pod IP 不再属于本节点，清理旧规则。
- 效果：规则随 Pod 迁移自动同步，无需手工干预。

## 6. 生效方式与效果总结
- 下发方式：节点守护进程调用 `update_map` 命令行更新 map。
- 生效位置：tc 挂载在 veth/桥/主网卡。
- 效果：
  - 白名单下，只有明确允许的流量能通过。
  - Pod 漂移后规则自动迁移。
  - 共享规则保证短暂空窗期可控。
  - 命中 allow 的回包在 TTL 内自动放行（stateful）。
