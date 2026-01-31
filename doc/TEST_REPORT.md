# 测试报告（kind 模拟集群）

日期：2026-02-01

## 1. 测试目标
- 清理旧的测试环境与 iptables 相关测试影响。
- 重建 kind 集群，尽量贴近生产版本（K8s v1.28.x）。
- 验证基础集群与功能性测试（跨节点通信、Pod 漂移）。

## 2. 环境说明
- 本地环境：macOS（Docker Desktop）
- kind 集群名：ebpf-ds-test
- Kubernetes Server 版本：v1.28.6（**接近**生产 v1.28.5）
- CNI：Calico v3.27.4（通过 jsDelivr 镜像下载 manifest）
- 节点 OS：Debian GNU/Linux 12（与生产 Kylin V10 不同）
- 运行时：containerd://1.7.13

> 版本偏差说明：
> - 生产：CCE 24.11.2 / K8s v1.28.5 / Kylin V10 / Calico v3.27.4-dirty
> - 测试：kind v1.28.6（仅 patch 差异）/ Debian 12 / Calico v3.27.4
> - CCE 无法在 kind 中完全模拟，已按 K8s 版本尽量对齐。

## 3. 测试步骤
### 3.1 清理测试环境
- 删除旧 kind 集群（ms-dev）。

### 3.2 重新创建 kind 集群
- 使用配置创建 1 控制面 + 2 工作节点。
- 启用默认 CNI（kindnet），设置 Pod 子网：10.244.0.0/16。
- 使用缓存镜像 kindest/node:v1.28.6 创建集群。

### 3.3 Calico 安装（完成）
- 通过 jsDelivr 镜像下载 Calico v3.27.4 manifest 并成功应用。
- Calico Node、kube-controllers 与 CoreDNS 均进入 Ready。

### 3.4 验证
- `kubectl get nodes -o wide`：三节点 Ready。
- `kubectl get pods -n kube-system`：核心系统组件运行。

### 3.5 功能验证
#### 3.5.1 基线连通性（无策略）
测试负载与 IP：
- `curl-client`：10.244.119.66（worker2）
- `curl-client-2`：10.244.200.131（worker）
- `echo-server`：10.244.119.67（worker2）
- `echo-server-2`：10.244.200.132（worker）
- `multi-a`：10.244.119.68（worker2，具备 curl + HTTP 服务）

验证：
- `curl-client -> echo-server` 返回 `hello`。
- `curl-client-2 -> echo-server` 返回 `hello`。
- `curl-client -> echo-server-2` 返回 `hello-2`。
- `curl-client-2 -> echo-server` 返回 `hello`。

#### 3.5.2 同节点通信
- `curl-client` 与 `echo-server` 同节点：可达。

#### 3.5.3 跨节点通信
- `curl-client-2`（worker）访问 `echo-server`（worker2）：可达。

#### 3.5.4 Pod 漂移
- `echo-server` 漂移后服务仍可达。

### 3.6 eBPF DaemonSet 部署
- 使用本地构建镜像 `k8s-ebpf/k8s-ebpf:1.0.0`，通过 kind 直接加载到各节点。
- DaemonSet 在 3 个节点全部 Ready。
- Actuator 健康检查通过：`/actuator/health` 返回 `UP`。

### 3.7 eBPF 规则下发与拦截验证
- DaemonSet 自动执行 `update_map start eth0`，完成 eBPF 加载与 map 固定。
- 自动识别并挂载 `veth*`/`cali*` 接口，覆盖同节点 Pod 通信。
- 下发规则：`src=10.244.119.66 -> dst=10.244.119.67:5678/TCP`，动作为 `drop`。
- 期望：`curl-client` 访问 `echo-server` 超时/失败。
- 实际：请求超时（被拦截）。
- 删除规则后，访问恢复正常（返回 `hello`）。

### 3.8 问题修复与回归
问题 1：`policy_mode` map 旧实例残留导致白名单不生效。
- 现象：`update_map mode set` 成功，但 egress 白名单不拦截。
- 修复：`update_map start` 清理旧的 `/sys/fs/bpf/tc_filter_policy_mode` 与 `/sys/fs/bpf/tc_filter_endpoint_rules`，确保新程序重新 pin map。

问题 2：Pod 出向流量在宿主机侧以 ingress 形式出现，导致 egress 判断失效。
- 现象：eBPF 仅按 `skb->ingress_ifindex` 区分方向，出向白名单未生效。
- 修复：在 eBPF 中同时检查 `dst/ingress` 与 `src/egress` 白名单，确保出向在 host ingress 场景也能拦截。

回归：修复后 egress 白名单拦截恢复正常（见 3.10）。

### 3.9 白名单模式（Ingress）验证
测试对象：
- 目标 Pod：`echo-server`（Pod IP `10.244.119.67`）
- 允许源：`curl-client`（Pod IP `10.244.119.66`）
- 拒绝源：`curl-client-2`（Pod IP `10.244.200.131`）

步骤：
- 设置白名单入向模式：`update_map mode set 10.244.119.67 ingress`。
- 添加放行规则：`update_map add 10.244.119.66 10.244.119.67 5678 6 accept`。

验证结果：
- 允许源访问 Pod IP：`curl-client -> 10.244.119.67:5678` 返回 `hello`。
- 拒绝源访问 Pod IP：`curl-client-2 -> 10.244.119.67:5678` 超时。

### 3.10 白名单模式（Egress）验证
场景说明：仅配置出向白名单，目标 Pod 只能访问被允许的远端，访问其他远端必须被拦截。

测试对象：
- 目标 Pod（出向受控）：`multi-a`（Pod IP `10.244.119.68`）
- 允许远端：`echo-server`（Pod IP `10.244.119.67`）
- 非允许远端：`echo-server-2`（Pod IP `10.244.200.132`）

步骤：
- 设置白名单出向模式：`update_map mode set 10.244.119.68 egress`。
- 添加放行规则：`update_map add 10.244.119.68 10.244.119.67 5678 6 accept`。

验证结果：
- 允许远端：`multi-a -> 10.244.119.67:5678` 返回 `hello`。
- 非允许远端：`multi-a -> 10.244.200.132:5678` 超时（访问被拒绝）。

### 3.11 白名单模式（Ingress + Egress）验证（ICMP）
场景说明：同时配置入向与出向白名单，使用 ICMP 验证双向放行（避免 TCP 回包端口不可预测问题）。

测试对象：
- 目标 Pod：`multi-a`（Pod IP `10.244.119.68`）
- 允许对端：`echo-server`（Pod IP `10.244.119.67`）
- 非允许对端：`echo-server-2`（Pod IP `10.244.200.132`）

步骤：
- 设置双向白名单：`update_map mode set 10.244.119.68 both`。
- 放行 ICMP 双向：
	- `update_map add 10.244.119.68 10.244.119.67 0 1 accept`
	- `update_map add 10.244.119.67 10.244.119.68 0 1 accept`

验证结果：
- `multi-a -> 10.244.119.67` ping 成功。
- `multi-a -> 10.244.200.132` ping 丢包（被拦截）。

### 3.12 白名单反向测试（业务语义验证）
场景说明：配置 A 出向白名单仅允许访问 B，则 A 只能访问 B；A 访问 C 必须失败；B/C 访问 A 也必须失败（不因 A 的出向白名单自动放行）。

映射到本次测试对象：
- A：`multi-a`（10.244.119.68）
- B：`echo-server`（10.244.119.67）
- C：`echo-server-2`（10.244.200.132）

验证要点与结果：
- A -> B：成功（已添加出向放行规则）。
- A -> C：失败（未添加出向放行规则，超时）。
- B/C -> A：失败（A 处于出向白名单时，返回流量被拦截，表现为超时）。

说明：当前实现为无状态过滤，A 的出向白名单会影响回包方向；若业务需要在保证 A 出向受控的同时允许 B/C 主动访问 A，需要显式加入回包/入向放行规则或引入状态跟踪机制。

## 4. 关键结果
- 集群已重建，历史 iptables 测试影响被清理（环境完全重新生成）。
- K8s 版本为 v1.28.6，满足与生产 v1.28.5 的 **同 minor** 要求。
- Pod 漂移/同节点/跨节点场景验证通过（服务访问连续）。
- eBPF DaemonSet 部署成功，规则下发与拦截验证通过。
- 白名单模式（Ingress/Egress/双向 ICMP）验证通过：允许源放行、非允许源默认拒绝。
- 修复 `policy_mode` pin 与方向判定问题后，eBPF 白名单生效。

## 5. 风险与差异说明
- **CCE 24.11.2** 无法在 kind 中完全模拟，仅能对齐 K8s 版本。
- **操作系统** 与生产不同（Debian vs Kylin），内核/驱动行为可能存在差异。
- **eBPF 规则下发验证**：已完成基础规则下发与拦截验证。
- **Calico 接口前缀**：`veth*`/`cali*` 自动挂载已验证生效。
- **无状态限制**：在 TCP 场景下，出向白名单会影响回包方向；需要显式放行回包或引入状态跟踪。

## 6. 结论
- 测试环境已按要求重装并清理。
- Pod 漂移/同节点/跨节点基础功能验证通过。
- 规则同步的完整链路（含 eBPF 下发）已在 kind+Calico 环境完成基础验证。
- 白名单模式的入向/出向/双向与反向语义已验证，并记录无状态限制。
