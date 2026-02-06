# 云下部署步骤（可直接照做）

适用场景：在云下虚拟机上直接运行本程序（不使用 Docker），通过对外访问 Nginx 的连通性展示入向/出向被管控。

---

## 0. 前提信息准备

请先确认并记录以下信息（后续步骤会用到）：

- 云下 VM 的对外 IP：`<VM_IP>`
- Nginx 对外监听端口：`<NGINX_PORT>`（通常 80 或 443）
- 本程序监听端口：`<APP_PORT>`（默认 8080）
- 网卡名：`<IFACE>`（常见为 eth0/ens*）

> 关键判断：规则里使用的目标 IP/端口，就是客户端实际访问到的对外 IP/端口。

---

## 1. 环境要求检查

### 1.1 基础依赖

云下 VM 需要满足：
- Linux 内核支持 eBPF（建议 5.x 以上）
- 已安装 JRE 8（Java 8 运行时）
- 具备 `tc` 工具（通常来自 `iproute2`）

**验证点**
- 能运行 `java -version`
- 能运行 `tc -V`

### 1.2 未安装 JRE/tc 时的处理

如果提示 `java: command not found` 或 `tc: command not found`，说明基础依赖未安装。请根据系统类型安装：

**Debian/Ubuntu**
- 安装 JRE：安装 `openjdk-8-jre-headless`
- 安装 tc：安装 `iproute2`

**CentOS/RHEL/Rocky/Alma/Kylin**
- 安装 JRE：安装 `java-1.8.0-openjdk-headless`
- 安装 tc：安装 `iproute`

**SLES 12**
- 安装 JRE：安装 `java-1_8_0-openjdk`
- 安装 tc：安装 `iproute2`

安装完成后进行验证：
- `tc -V`
- `java -version`

### 1.3 需要开放的端口

- 本程序：`<APP_PORT>`
- Nginx：`<NGINX_PORT>`

**验证点**
- `ss -lntp` 中能看到对应端口监听

---

## 2. 部署程序文件

将以下文件复制到云下 VM，并放在固定目录 `/app/`（避免改脚本路径）：
- `k8s-ebpf-1.0-SNAPSHOT.jar`
- `tc_filter.bpf.o`
- `update_map`
- `config/` 目录
- `entrypoint.sh`

**验证点**
- `/app` 目录内文件齐全
- `update_map` 可执行（`chmod +x /app/update_map`）
- `entrypoint.sh` 可执行（`chmod +x /app/entrypoint.sh`）

---

## 3. 启动程序（云下模式）

推荐使用 systemd 运行，便于演示稳定。

### 3.1 systemd 服务文件示例

创建 `/etc/systemd/system/k8s-ebpf.service`，内容示例：

```
[Unit]
Description=K8s eBPF Offcloud Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/app
Environment=SIMPLIFIED_MODE=true
Environment=EBPF_AUTO_START=true
Environment=IFACE=<IFACE>
ExecStartPre=/bin/sh -c 'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf'
ExecStart=/app/entrypoint.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

- 关键点：
  - 设置 `SIMPLIFIED_MODE=true`
  - 以 root 运行
  - 指定网卡名 `IFACE`（例如 eth0/ens33）
  - 挂载 `bpffs`（如果宿主未自动挂载）

启动与验证：
- `systemctl daemon-reload`
- `systemctl enable --now k8s-ebpf`

**验证点**
- `systemctl status k8s-ebpf` 显示运行中
- `http://127.0.0.1:<APP_PORT>/actuator/health` 可访问

> 如果不使用 systemd，可直接以 root 执行 `/app/entrypoint.sh` 启动。

---

## 4. 绑定网卡与 eBPF

启动后，确认 eBPF 程序已挂到正确网卡：

**验证点**
- `tc qdisc show dev <IFACE>` 能看到 `clsact`
- `tc filter show dev <IFACE> ingress` / `egress` 能看到 bpf 过滤器

如果没有挂载，检查：
- 是否有 root 权限
- 是否启用 `SIMPLIFIED_MODE`
- 宿主机内核是否支持 eBPF

---

## 5. 演示：出向管控（Egress）

### 5.1 基准验证

从受控端（云下 VM 或受控容器）访问 Nginx：
- 访问 `http://<VM_IP>:<NGINX_PORT>` 应该成功

### 5.2 下发阻断规则

使用接口添加 egress 拦截规则（目标为 `<VM_IP>:<NGINX_PORT>`）

**验证点**
- 访问失败（超时或被拒绝）

### 5.3 删除规则

删除规则后再次访问

**验证点**
- 访问恢复成功

---

## 6. 演示：入向管控（Ingress）

### 6.1 基准验证

在外部机器访问云下 VM 的应用端口 `<APP_PORT>`：
- `http://<VM_IP>:<APP_PORT>/actuator/health` 成功

### 6.2 下发阻断规则

添加 ingress 规则，拦截到 `<APP_PORT>`

**验证点**
- 外部访问失败

### 6.3 删除规则

删除规则后恢复访问

**验证点**
- 外部访问成功

---

## 7. 常见问题排查

1) 规则没生效
- 检查网卡是否正确
- 检查是否命中正确 IP/端口
- 检查是否在期望方向（ingress/egress）

2) 无法挂载 eBPF
- 内核版本不支持
- 权限不足（需 root/privileged）
- bpffs 未挂载

3) 健康检查失败
- 程序未启动或端口冲突
- `SIMPLIFIED_MODE` 未开启

---

## 8. 演示建议流程（固定模板）

1) 基准连通
2) 下发阻断规则
3) 验证阻断
4) 删除规则
5) 验证恢复

---

如需我补充**具体接口请求体**或**systemd 完整示例**，告诉我你的实际端口、网卡名和访问路径。
