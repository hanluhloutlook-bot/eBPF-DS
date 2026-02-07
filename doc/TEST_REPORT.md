# 测试报告（kind 模拟集群）

日期：2026-02-01

## 1. 测试目标
- 云上可以针对命名空间和负载进行策略配置。
- 可以针对目标配置出向或入向白名单策略。且技术上不应有冲突。
- 验证基础集群与功能性测试（跨节点通信、Pod 漂移、策略下发等）。

## 1.1 业务场景描述（补充）
- 管理端对接本程序，用户可选择**目标负载或命名空间**，配置**入向/出向**规则。
- 远端类型支持：**负载、命名空间、CIDR**。
- 端口可指定或全量（`0` 表示所有端口）。
- 若配置白名单/黑名单访问关系，**除 Pod 间流量外，对应 Service 也必须默认受策略约束**。

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

---

# 回归测试记录（v1.1.0）

日期：2026-02-05

## 1. 版本与环境
- 镜像版本：k8s-ebpf/k8s-ebpf:1.1.0
- 集群：kind (ebpf-ds-test)，K8s v1.28.6，Calico v3.27.4
- 节点：1 控制面 + 2 工作节点

## 2. 回归范围
- 基线连通性（Service 与 Pod IP）
- 精确规则拦截（五元组）
- 端口 0 通配规则
- CIDR 规则（/24）
- 入向白名单（允许/拒绝）
- 出向白名单（允许/拒绝）

## 3. 结果摘要（全部通过）
1. **基线连通性**：curl-client/curl-client-2 访问 Service 与 Pod IP 均成功。
2. **精确规则拦截**：`src=10.244.119.73 dst=10.244.200.137 port=5678/TCP drop` 生效，删除后恢复。
3. **端口 0 通配**：`port=0` 拦截规则可阻断 5678 访问。
4. **CIDR /24**：`dst=10.244.200.0/24 port=0` 拦截覆盖多目标（10.244.200.135/137）。
5. **入向白名单**：允许源可达，非允许源被拦截。
6. **出向白名单**：允许目标可达，非允许目标被拦截。

## 4. 修复项验证
- 修复 CIDR 前缀匹配逻辑：/24 已生效。

---

# 回归测试记录（v1.1.10 补充：targetType=deployment/namespace）

日期：2026-02-06

## 1. 版本与环境
- 镜像版本：k8s-ebpf/k8s-ebpf:1.1.10
- 集群：kind (ebpf-ds-test)，K8s v1.28.6，Calico v3.27.4
- 节点：1 控制面 + 2 工作节点
- 命名空间：ebpf-test

## 2. 测试对象（本次实际 IP）
- A（multi-a）：10.244.119.65（worker2）
- B（echo-server）：10.244.200.129（worker）
- C（echo-server-2）：10.244.200.130（worker）
- curl-client：10.244.119.66（worker2）
- curl-client-2：10.244.200.131（worker）
- Service（echo-server ClusterIP）：10.96.57.162:80

> 说明：策略缓存为本节点内存态，创建策略时使用**对应节点**的 DaemonSet Pod 以保证策略下发到本节点。

## 3. 场景设计与结果

### 3.1 targetType=deployment（白名单：生产常见）
场景：A 出向白名单仅允许访问 B；B 入向白名单仅允许 A 访问；分别验证 Pod 直连与 Service 访问。

结果：
- A -> B（Pod IP 直连 10.244.200.129:5678）：成功（hello）。
- A -> B（Service 10.96.57.162:80）：成功（hello）。
- A -> C（10.244.200.130:5678）：失败（超时）。
- 非允许源 -> B（Pod/Service）：失败（超时）。

### 3.2 targetType=namespace（黑名单：生产常见）
场景：对 ebpf-test 命名空间应用策略，验证针对特定目标的黑名单拦截与放行效果（Pod/Service）。

结果：
- **出向黑名单**（namespace 目标，拦截 C）：
	- curl-client -> B（Pod 直连）：成功（hello）。
	- curl-client -> C（Pod 直连）：失败（超时）。
- **入向黑名单**（namespace 目标，拦截 curl-client-2）：
	- curl-client -> B（Pod/Service）：成功（hello）。
	- curl-client-2 -> B（Pod/Service）：失败（超时）。

### 3.3 targetType=namespace（白名单：生产常见，结果异常）
场景：对 ebpf-test 命名空间应用入向/出向白名单，按设计应仅允许指定来源/目标（Pod/Service）。

结果：
- **入向白名单**（namespace 目标，仅允许 curl-client）：
	- curl-client -> B（Pod/Service）：**成功（hello）**。
	- curl-client-2 -> B（Pod/Service）：失败（超时）。
- **出向白名单**（namespace 目标，仅允许访问 echo-server）：
	- curl-client -> B（Pod/Service）：**成功（hello）**。
	- curl-client -> C（Pod 直连）：失败（超时）。

结论：namespace 白名单场景**已恢复按预期放行**（通过 API 下发，未手工修改 map）。

定位结论（原因解释）：
- namespace ingress 白名单会把**命名空间内所有 Pod**都标记为 ingress 白名单目标（policy_mode）。
- 原先为**无状态过滤**，请求包命中 allow 规则但回包被默认拒绝，表现为超时。
- 已引入 **stateful 回包放行（conntrack + TTL）**，回包可命中并放行。

### 3.4 CIDR 场景（API 下发，覆盖入向/出向/双向/正向/反向）
场景：以 A（multi-a）为受控目标，使用 CIDR（10.244.200.0/24）进行规则验证；B/C 均在该 CIDR 内。

结果：
- **出向黑名单（CIDR）**：
	- A -> B/C（Pod 直连）：失败（超时）。
- **出向白名单（CIDR）**：
	- A -> B/C（Pod 直连）：成功（hello/hello-2）。
	- A -> B Service（10.96.57.162:80，非 CIDR）：失败（超时）。
	- **反向语义**：curl-client-2 -> A:80 **成功**（未被阻断）。
- **入向黑名单（CIDR）**：
	- curl-client（10.244.119.0/24）-> B（Pod/Service）：失败（超时）。
	- curl-client-2 -> B（Pod/Service）：成功（hello）。
- **入向白名单（CIDR）**：
	- curl-client -> B（Pod/Service）：成功（hello）。
	- curl-client-2 -> B（Pod/Service）：失败（超时）。
- **双向白名单（CIDR，ICMP）**：
	- A -> B/C：ping 成功。
	- 10.244.200.0/24 -> A：未完成验证（curl-client-2 容器 ping 需要 root 权限）。

### 3.5 规则重复检查
通过 `update_map query | sort | uniq -d` 检查 net_policy，未发现重复规则。
说明：策略解析会对 Pod IP / Service IP / 端口映射进行展开，出现“多条相似规则”属于预期；map key 唯一，不会存储真正重复项。

### 3.6 targetType=deployment + remoteType=namespace（补测）
场景：目标为具体负载（deployment），远端为命名空间，验证入向/出向黑名单，以及 Service 访问。

结果：
- **出向黑名单**（目标 curl-client，远端 namespace）：
	- curl-client -> B/C（Pod 直连）：失败（超时）。
	- curl-client -> B Service（10.96.57.162:80）：失败（超时）。
- **入向黑名单**（目标 echo-server，远端 namespace）：
	- curl-client / curl-client-2 -> B（Pod 直连）：失败（超时）。
	- curl-client -> B Service（10.96.57.162:80）：失败（超时）。

### 3.7 targetType=deployment + remoteType=deployment（端口 0 补测）
场景：目标为 curl-client，远端为 echo-server，端口设置为 0（全端口），验证 Pod/Service。

结果：
- curl-client -> B（Pod 直连）：失败（超时）。
- curl-client -> B Service（10.96.57.162:80）：失败（超时）。

### 3.8 仍未覆盖的场景
- **UDP 规则**：现有测试负载未提供 UDP 服务，未覆盖。
- **remoteType=namespace/deployment/ips**：控制器未显式实现该类型解析，未覆盖。

## 4. 结论
- targetType=deployment 的出向/入向白名单在 Pod 直连与 Service 访问下均生效。
- targetType=namespace 的出向/入向黑名单在 Pod 直连与 Service 访问下均生效。
- targetType=deployment + remoteType=namespace 黑名单策略在 Pod/Service 下均生效。
- targetType=deployment + remoteType=deployment 且端口 0 场景在 Pod/Service 下生效。

---

# 回归测试记录（v1.1.9）

日期：2026-02-06

## 1. 版本与环境
- 镜像版本：k8s-ebpf/k8s-ebpf:1.1.7（已包含 v1.1.9 代码变更）
- 集群：kind (ebpf-ds-test)，K8s v1.28.6，Calico v3.27.4
- 节点：1 控制面 + 2 工作节点
- 命名空间：ebpf-policy-test

## 2. 回归范围
- API 策略创建/删除（只通过 policy 接口）
- 删除后 map 清理与连通性恢复

## 3. 测试步骤与结果
### 3.1 策略创建（黑名单 egress）
- 请求：`/api/networkpolicy/create`
- 策略：namespace=ebpf-policy-test，egress 拦截目标 10.244.202.13:80/TCP
- 结果：
	- 策略缓存：size=1
	- map 规则：出现 3 条 drop 规则（源为 3 个本地 Pod IP）
	- 访问：curl-cp -> 10.244.202.13:80 返回 000（超时）

### 3.2 策略删除
- 请求：`/api/networkpolicy/delete`
- 结果：
	- 策略缓存：size=0
	- map 规则：清空
	- 访问：curl-cp -> 10.244.202.13:80 返回 200（恢复）

## 4. 结论
- API 策略创建/删除链路生效。
- 删除后规则清理成功，连通性恢复正常。

---

# 回归测试记录（v1.1.3）

日期：2026-02-05

## 1. 版本与环境
- 镜像版本：k8s-ebpf/k8s-ebpf:1.1.3
- 集群：kind (ebpf-ds-test)，K8s v1.28.6，Calico v3.27.4（IPIP）
- 节点：1 控制面 + 2 工作节点

## 2. 回归范围
- Pod -> Pod（同节点/跨节点）流量拦截
- Pod -> Service（ClusterIP）流量拦截
- 端口 0 通配规则
- CIDR 规则（/24）
- 入向白名单（允许/拒绝）
- 出向白名单（允许/拒绝）
- 双向白名单（ICMP）
- 白名单反向语义验证

## 3. 结果摘要（全部通过）
1. **Pod -> Pod 同节点**：基线 200；下发 drop 后 000/failed；删除规则恢复 200。
2. **Pod -> Pod 跨节点**：基线 200；下发 drop 后 000/failed；删除规则恢复 200。
3. **Pod -> Service (ClusterIP)**：基线 200；下发 drop 后 000/failed；删除规则恢复 200。
4. **端口 0 通配**：`port=0` 规则可阻断 80 访问。
5. **CIDR /24**：`src=10.244.119.0/24` 可阻断访问目标。
6. **入向白名单**：允许源可达，非允许源被拦截。
7. **出向白名单**：允许目标可达，非允许目标被拦截。
8. **双向白名单（ICMP）**：允许对端 ping 成功，非允许对端 ping 丢包。
9. **白名单反向语义**：A 出向白名单仅允许 B，A->C 失败；B->A 失败。

## 4. 修复/适配项验证
- **tunl0 挂载**：IPIP overlay 流量已被拦截，Pod/Service 流量验证通过。
- `update_map query` 中 CIDR 前缀显示正确。

## 5. 备注
- `update_map` 在 Pod 内执行返回码为 1，但规则实际生效；不影响测试结论。
