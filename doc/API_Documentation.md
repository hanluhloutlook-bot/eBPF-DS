# 网络策略管理 API 文档

## 概述

本文档描述了网络策略管理系统的 REST API 接口，用于创建网络策略、添加规则、启动和停止 eBPF 程序。

## API 基础路径

所有 API 端点都以 `/api/networkpolicy` 为基础路径。

## API 端点列表

### 1. 创建网络策略

#### 请求信息
- **路径**: `/api/networkpolicy/create`
- **方法**: `POST`
- **内容类型**: `application/json`
- **请求体**: `NetworkPolicyRequest` 对象

#### 请求体格式
```json
{
  "clusterName": "hqnt-cceeiet-qcloud-a-hgx86",
  "namespace": "hb-qcloud1",
  "name": "允许下游访问",
  "targetObject": {
    "type": "namespace",
    "name": "hb-qcloud1"
  },
  "createUser": "zhangyiyfwh",
  "policyMode": "whitelist",
  "ingressMode": "whitelist",
  "egressMode": "blacklist",
  "egressList": [
    {
      "protocol": "TCP",
      "port": 18092,
      "remoteType": "deployment",
      "remoteNamespace": "hb-qcloud1",
      "remoteName": "deployment_name"
    }
  ],
  "ingressList": [
    {
      "protocol": "UDP",
      "port": 18095,
      "remoteType": "ips",
      "remoteNamespace": "",
      "remoteName": "10.0.0.0/24,10.1.2.3"
    }
  ]
}
```

#### 必填/可选说明
- **必填**: `namespace`、`name`、`targetObject.type`、`targetObject.name`
- **可选**: `clusterName`、`createUser`、`egressList`、`ingressList`、`policyMode`、`ingressMode`、`egressMode`
- **说明**: 当 `ingressMode`/`egressMode` 未设置时，使用 `policyMode`；`policyMode` 未设置时默认 `blacklist`。

#### 响应信息
- **成功响应**: `Network policy created successfully`
- **错误响应**: `Error creating network policy: [错误信息]`

#### 示例请求
```bash
curl -X POST http://localhost:8080/api/networkpolicy/create \
  -H "Content-Type: application/json" \
  -d @input.json
```

### 2. 添加单个规则

#### 请求信息
- **路径**: `/api/networkpolicy/add-rule`
- **方法**: `POST`
- **内容类型**: `application/json`
- **请求体**:
  - `src`: 源 IP 地址（必填）
  - `dst`: 目标 IP 地址（必填）
  - `port`: 端口号（必填，`0` 表示所有端口）
  - `proto`: 协议编号（必填，6=TCP, 17=UDP, 1=ICMP）
  - `action`: 动作（必填，`allow` 或 `drop`）

#### 响应信息
- **成功响应**: `Rule added successfully`
- **错误响应**: `Error adding rule: [错误信息]`

#### 示例请求
```bash
curl -X POST http://localhost:8080/api/networkpolicy/add-rule \
  -H "Content-Type: application/json" \
  -d '{"src":"192.168.59.11","dst":"192.168.59.10","port":23,"proto":6,"action":"drop"}'
```

### 3. 启动 eBPF 程序

#### 请求信息
- **路径**: `/api/networkpolicy/start-ebpf`
- **方法**: `POST`
- **内容类型**: `application/json`
- **请求体**:
  - `interfaceName`: 网络接口名称（必填，例如: ens33）

#### 响应信息
- **成功响应**: `successfully start EBPF service`
- **错误响应**: `Error starting EBPF program: [错误信息]`

#### 示例请求
```bash
curl -X POST http://localhost:8080/api/networkpolicy/start-ebpf \
  -H "Content-Type: application/json" \
  -d '{"interfaceName":"ens33"}'
```

#### 实现说明
此接口通过调用 `./update_map start <interfaceName>` 命令来启动eBPF程序，该命令会根据update_map.c中startEBPF()函数的具体实现来加载过滤器到指定的网络接口。

### 4. 停止 eBPF 程序

#### 请求信息
- **路径**: `/api/networkpolicy/stop-ebpf`
- **方法**: `POST`
- **内容类型**: `application/json`
- **请求体**:
  - `interfaceName`: 网络接口名称（必填，例如: ens33）

#### 响应信息
- **成功响应**: `EBPF program stopped successfully`
- **错误响应**: `Error stopping EBPF program: [错误信息]`

#### 示例请求
```bash
curl -X POST http://localhost:8080/api/networkpolicy/stop-ebpf \
  -H "Content-Type: application/json" \
  -d '{"interfaceName":"ens33"}'
```

### 5. 删除网络策略

#### 请求信息
- **路径**: `/api/networkpolicy/delete`
- **方法**: `POST`
- **内容类型**: `application/json`
- **请求体**: `NetworkPolicyRequest`（仅使用 `clusterName`/`namespace`/`name` 字段）
  - `clusterName`: 集群名称（可选）
  - `namespace`: 命名空间（必填）
  - `name`: 策略名称（必填）

#### 响应信息
- **成功响应**: `Network policy deleted successfully`
- **错误响应**: `Error deleting network policy: [错误信息]`

#### 示例请求
```bash
curl -X POST http://localhost:8080/api/networkpolicy/delete \
  -H "Content-Type: application/json" \
  -d '{"clusterName":"demo","namespace":"default","name":"policy-1"}'
```

### 6. 删除单个规则

#### 请求信息
- **路径**: `/api/networkpolicy/delete-rule`
- **方法**: `POST`
- **内容类型**: `application/json`
- **请求体**:
  - `src`: 源 IP 地址（必填）
  - `dst`: 目标 IP 地址（必填）
  - `port`: 端口号（必填，`0` 表示所有端口）
  - `proto`: 协议编号（必填，6=TCP, 17=UDP, 1=ICMP）

#### 响应信息
- **成功响应**: `Rule deleted successfully`
- **错误响应**: `Error deleting rule: [错误信息]`

#### 示例请求
```bash
curl -X POST http://localhost:8080/api/networkpolicy/delete-rule \
  -H "Content-Type: application/json" \
  -d '{"src":"192.168.59.11","dst":"192.168.59.10","port":23,"proto":6}'
```

## 数据结构

### NetworkPolicyRequest
| 字段名 | 类型 | 描述 |
|--------|------|------|
| clusterName | String | 集群名称（可选） |
| namespace | String | 命名空间（必填） |
| name | String | 策略名称（必填） |
| targetObject | TargetObject | 目标对象（必填） |
| createUser | String | 创建用户（可选） |
| egressList | List<EgressRule> | 出站规则列表（可选） |
| ingressList | List<IngressRule> | 入站规则列表（可选） |
| policyMode | String | 全局策略模式（可选）：`whitelist`（未命中即拒绝）或 `blacklist`（未命中即放行），默认 `blacklist` |
| ingressMode | String | 入站策略模式（可选）：`whitelist` 或 `blacklist`（覆盖 `policyMode`） |
| egressMode | String | 出站策略模式（可选）：`whitelist` 或 `blacklist`（覆盖 `policyMode`） |

### TargetObject
| 字段名 | 类型 | 描述 |
|--------|------|------|
| type | String | 目标对象类型（必填）：`namespace/deployment`、`namespace`、`ips` |
| name | String | 目标对象名称（必填）：`namespace/deployment` 为 deployment 名；`namespace` 为目标命名空间（为空则使用请求中的 `namespace`）；`ips` 为 IP/CIDR 列表 |

### Rule (基类)
| 字段名 | 类型 | 描述 |
|--------|------|------|
| protocol | String | 协议（必填）：`TCP`、`UDP`、`ICMP`，或直接传协议号（如 `6`/`17`/`1`） |
| port | int | 端口号（必填，`0` 表示所有端口） |
| remoteType | String | 远程对象类型（必填）：`deployment`、`namespace`、`ips`、`namespace/deployment/ips` |
| remoteNamespace | String | 远程命名空间（`remoteType` 为 `deployment`/`namespace`/`namespace/deployment/ips` 时必填） |
| remoteName | String | 远程对象名称（必填）：`deployment` 名；或 `ips` 时的 IP/CIDR 列表；`namespace/deployment/ips` 时为 deployment 名 |

> 说明：当 `remoteType=ips` 或 `targetObject.type=ips` 时，`remoteName` / `targetObject.name` 支持多个 IP 或 CIDR，使用英文逗号分隔（例如：`10.0.0.1,10.0.0.0/24`）。

> 说明：当 `remoteType` 为 `deployment`、`namespace` 或 `namespace/deployment/ips` 时，会解析实际 Pod IP，并在存在 Service 的情况下自动包含对应 Service ClusterIP 与端口映射（仅匹配目标端口）。

> 说明：CIDR 前缀 **小于 32** 时，仅按 IP 前缀匹配（不区分端口/对端 IP）；前缀 **等于 32** 时按完整四元组匹配。

## 云下部署（虚拟机）

在云下或非 K8s 环境使用时，可通过 `systemd` 管理进程（需 root 权限，确保二进制与 `update_map` 在同目录）。示例：

```ini
[Unit]
Description=eBPF Network Policy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/ebpf
ExecStart=/opt/ebpf/NetworkPolicyApplication --spring.config.location=/opt/ebpf/application.properties
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

### EgressRule
继承自 Rule，用于出站规则。

### IngressRule
继承自 Rule，用于入站规则。

## 注意事项

1. **权限要求**: 由于需要操作 eBPF 和 TC 规则，应用需要以 root 用户或具有 sudo 权限的用户运行。

2. **Kubernetes 依赖**: 当连接到 Kubernetes API 服务器时，会尝试获取实际的 Pod IP 地址；如果无法连接，则会使用占位符 IP 地址。

3. **eBPF 程序**: 启动 eBPF 程序时，需要确保 `tc_block_filter.bpf.o` 和 `tc_egress_filter.bpf.o` 文件存在于应用的工作目录中。

4. **update_map 工具**: 启动和添加规则时，都需要确保 `update_map` 工具存在于应用的工作目录中，因为这两个操作都依赖此工具。

## 错误处理

所有 API 端点都会返回人类可读的错误消息，格式为:
- 成功: 返回成功消息字符串
- 失败: 返回错误消息字符串，包含具体错误信息

## 示例工作流

1. **启动 eBPF 程序**:
   ```bash
   curl -X POST http://localhost:8080/api/networkpolicy/start-ebpf \
     -H "Content-Type: application/json" \
     -d '{"interfaceName":"ens33"}'
   ```

2. **添加规则**:
   ```bash
   curl -X POST http://localhost:8080/api/networkpolicy/add-rule \
     -H "Content-Type: application/json" \
     -d '{"src":"192.168.59.10","dst":"192.168.59.11","port":8081,"proto":6,"action":"drop"}'
   ```

3. **创建网络策略**:
   ```bash
   curl -X POST http://localhost:8080/api/networkpolicy/create \
     -H "Content-Type: application/json" \
     -d @input.json
   ```

4. **停止 eBPF 程序**:
   ```bash
   curl -X POST http://localhost:8080/api/networkpolicy/stop-ebpf \
     -H "Content-Type: application/json" \
     -d '{"interfaceName":"ens33"}'
   ```