# eBPF-DS 架构文档

## 1. 目标与范围
本项目用于集群内 eBPF 网络请求管控。核心能力是将应用层的网络策略转换为内核态 eBPF 规则，并通过 tc（Traffic Control）在指定网卡的 ingress/egress 上生效。

## 2. 总体架构
**分层与职责**：
- **控制平面（Java/Spring Boot）**：接收策略请求、解析对象范围、与 Kubernetes API 交互获取 Pod IP、缓存全量策略并定时仅下发本节点相关规则。
- **数据平面（eBPF + tc）**：`tc_filter.bpf.o` 在内核中匹配流量五元组（简化为 src/dst/port/proto），优先使用 endpoint 级规则（ifindex 绑定），并结合白名单管控模式执行 allow/drop。
- **运维/启动组件**：`update_map` C 程序负责加载/固定 eBPF 程序和 map，并提供 add/delete/query 管理入口；`Dockerfile` 和 `entrypoint.sh` 负责容器化启动。

## 3. 核心组件
### 3.1 Spring Boot 服务
- **入口**：`NetworkPolicyApplication` 启动 Spring 容器。
- **REST 控制器**：`NetworkPolicyController`
  - `/api/networkpolicy/create`：解析策略请求，将规则转换为 eBPF map 记录。
  - `/api/networkpolicy/delete`：删除已下发的规则。
  - `/api/networkpolicy/add-rule`、`/delete-rule`：直接操作单条规则。
  - `/start-ebpf`、`/stop-ebpf`：启动或清理 tc 规则。
  - `/query`：查询 map 中现有规则。
- **数据模型**：`NetworkPolicyRequest`、`Rule`、`EgressRule`、`IngressRule`、`TargetObject`。

### 3.2 辅助解析器
- **`NetworkPolicyParser`**：读取 `input.json`，通过 Kubernetes API 解析目标 Pod IP，并调用 `update_map` 更新 eBPF map。适合离线或脚本化场景。

### 3.3 轻量级 HTTP 服务
- **`NetworkPolicyServer`**：不依赖 Spring 的轻量级服务，启动后可接收 `GET /add?...` 更新规则，便于测试和简化部署。

### 3.4 eBPF 程序
- **`tc_filter.bpf.c`**：
  - map：`endpoint_rules`（Hash-of-Maps，按 ifindex 绑定）、`net_policy`（共享规则）、`policy_mode`（白名单管控方向）。
  - hook：`SEC("tc")` 对 ingress/egress 进行过滤，命中规则执行 allow/drop；未命中且处于白名单管控则默认拒绝。

### 3.5 eBPF 管理程序
- **`update_map.c`**：
  - `start`：加载 `tc_filter.bpf.o`，固定 program 与 map，并挂载 tc 规则。
  - `add`：向 map 写入规则。
  - `delete`：从 map 删除规则。
  - `query`：遍历 map 输出规则与计数。
  - `mode set/del`：设置/清理白名单管控模式。
  - `endpoint add/del/add-rule/del-rule`：管理 endpoint 级 map。

## 4. 关键流程
### 4.1 策略下发流程（REST）
1. 调用 `/api/networkpolicy/create`。
2. 控制器缓存全量策略，并定时获取本节点 Pod 列表。
3. 仅对本节点相关规则生成 `(src, dst, port, proto) -> action`。
4. 若已建立 endpoint 级 map，优先下发到 endpoint；否则写入共享 map，并设置 `policy_mode` 白名单管控。

### 4.2 eBPF 启动流程
1. 调用 `/start-ebpf` 或执行 `update_map start <iface>`。
2. `update_map` 加载 `tc_filter.bpf.o`，固定 program/map 到 `/sys/fs/bpf`。
3. 通过 tc 在主网卡、桥接口与 veth 上挂载 ingress/egress 过滤器（默认覆盖同节点流量）。

### 4.3 数据平面匹配流程
1. tc hook 进入 eBPF `tc_ingress`。
2. 从 IP 头构造 key（src/dst/port/proto）。
3. 查 `net_policy`：命中则计数并执行 drop/allow。

## 5. 目录与文件说明（核心）
- Java：`src/main/java/com/example/*`
- eBPF：`tc_filter.bpf.c`（程序）
- 用户态管理：`update_map.c`（管理工具）
- 构建与部署：`Makefile`、`Dockerfile`、`entrypoint.sh`、`daemonset.yaml`

## 6. 运行与依赖
- 需要内核支持 eBPF 与 tc。
- 需要 `libbpf`/`bpftool`（用于 map 访问与调试）。
- Kubernetes API 连接用于解析 Pod IP。

## 7. 关键设计注意点
- 通过固定 map 路径 `/sys/fs/bpf/tc_filter_endpoint_rules`、`/sys/fs/bpf/tc_filter_net_policy` 与 `/sys/fs/bpf/tc_filter_policy_mode` 共享给管理工具。
- 对内核 4.19 做兼容处理（去 BTF、严格模式）。
- 控制器支持简化模式（无法连 K8s API 时使用占位 IP）。
- 同节点通信通过 veth 挂载进行覆盖。
