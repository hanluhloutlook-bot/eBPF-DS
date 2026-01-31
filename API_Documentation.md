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
    "type": "namespace/deployment",
    "name": "hb01"
  },
  "createUser": "zhangyiyfwh",
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
      "remoteType": "namespace/deployment/ips",
      "remoteNamespace": "hb-qcloud1",
      "remoteName": "hb01"
    }
  ]
}
```

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
- **查询参数**:
  - `src`: 源 IP 地址
  - `dst`: 目标 IP 地址
  - `port`: 端口号
  - `proto`: 协议编号 (6=TCP, 17=UDP, 1=ICMP)
  - `action`: 动作 (accept 或 drop)

#### 响应信息
- **成功响应**: `Rule added successfully`
- **错误响应**: `Error adding rule: [错误信息]`

#### 示例请求
```bash
curl -X POST "http://localhost:8080/api/networkpolicy/add-rule?src=192.168.59.11&dst=192.168.59.10&port=23&proto=6&action=drop"
```

### 3. 启动 eBPF 程序

#### 请求信息
- **路径**: `/api/networkpolicy/start-ebpf`
- **方法**: `POST`
- **查询参数**:
  - `interfaceName`: 网络接口名称 (例如: ens33)

#### 响应信息
- **成功响应**: `successfully start EBPF service`
- **错误响应**: `Error starting EBPF program: [错误信息]`

#### 示例请求
```bash
curl -X POST "http://localhost:8080/api/networkpolicy/start-ebpf?interfaceName=ens33"
```

#### 实现说明
此接口通过调用 `./update_map start <interfaceName>` 命令来启动eBPF程序，该命令会根据update_map.c中startEBPF()函数的具体实现来加载过滤器到指定的网络接口。

### 4. 停止 eBPF 程序

#### 请求信息
- **路径**: `/api/networkpolicy/stop-ebpf`
- **方法**: `POST`
- **查询参数**:
  - `interfaceName`: 网络接口名称 (例如: ens33)

#### 响应信息
- **成功响应**: `EBPF program stopped successfully`
- **错误响应**: `Error stopping EBPF program: [错误信息]`

#### 示例请求
```bash
curl -X POST "http://localhost:8080/api/networkpolicy/stop-ebpf?interfaceName=ens33"
```

## 数据结构

### NetworkPolicyRequest
| 字段名 | 类型 | 描述 |
|--------|------|------|
| clusterName | String | 集群名称 |
| namespace | String | 命名空间 |
| name | String | 策略名称 |
| targetObject | TargetObject | 目标对象 |
| createUser | String | 创建用户 |
| egressList | List<EgressRule> | 出站规则列表 |
| ingressList | List<IngressRule> | 入站规则列表 |

### TargetObject
| 字段名 | 类型 | 描述 |
|--------|------|------|
| type | String | 目标对象类型 (例如: namespace/deployment) |
| name | String | 目标对象名称 |

### Rule (基类)
| 字段名 | 类型 | 描述 |
|--------|------|------|
| protocol | String | 协议 (TCP, UDP, ICMP) |
| port | int | 端口号 |
| remoteType | String | 远程对象类型 (deployment, namespace, ips, namespace/deployment/ips) |
| remoteNamespace | String | 远程命名空间 |
| remoteName | String | 远程对象名称 |

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
   curl -X POST "http://localhost:8080/api/networkpolicy/start-ebpf?interfaceName=ens33"
   ```

2. **添加规则**:
   ```bash
   curl -X POST "http://localhost:8080/api/networkpolicy/add-rule?src=192.168.59.10&dst=192.168.59.11&port=8081&proto=6&action=drop"
   ```

3. **创建网络策略**:
   ```bash
   curl -X POST http://localhost:8080/api/networkpolicy/create \
     -H "Content-Type: application/json" \
     -d @input.json
   ```

4. **停止 eBPF 程序**:
   ```bash
   curl -X POST "http://localhost:8080/api/networkpolicy/stop-ebpf?interfaceName=ens33"
   ```