# 云下部署步骤（逐步可复现）

适用场景：在云下虚拟机上直接运行本程序（不使用 Docker），通过对外访问 Nginx 的连通性展示入向/出向被管控。

---

## 0. 前提信息准备

请先确认并记录以下信息（后续步骤会用到）：

- 云下 VM 的对外 IP：`82.19.116.227`
- Nginx 对外监听端口：`8090`
- 本程序监听端口：`8080`
- 网卡名：`enp3s0`

> 关键判断：规则里使用的目标 IP/端口，就是客户端实际访问到的对外 IP/端口。

### 0.1 获取网卡名与本机 IP（命令）

1) `ip -o -4 addr show | awk '{print $2,$4}'`
2) 从输出中选出实际对外网卡（例如 eth0/ens33）
3) 记录网卡名为 `enp3s0`，记录 IP 为 `82.19.116.227`

---

## 1. 获取并解压云下运行包

交付物为分卷 ZIP（示例：`offcloud-package-1.1.10.z01/z02/z03` + `offcloud-package-1.1.10.zip`）。

### 1.1 Windows 解压

1) 将所有分卷文件放在同一目录
2) 右键 `.zip` → 7-Zip → 解压到当前目录

### 1.2 Linux 解压

1) 将所有分卷文件放在同一目录
2) `zip -s 0 offcloud-package-1.1.10.zip --out offcloud-package-1.1.10.full.zip`
3) `unzip offcloud-package-1.1.10.full.zip`

### 1.3 复制到云下 VM（你的目录：/home/appuser/agq）

1) 确认目录存在：`ls -la /home/appuser/agq`
2) 上传目录到 VM（示例）：`scp -r offcloud-package-1.1.10/* appuser@82.19.116.227:/home/appuser/agq/`
3) 授权：`sudo chmod +x /home/appuser/agq/update_map /home/appuser/agq/entrypoint.sh`

**验证点**
- `ls -la /home/appuser/agq` 能看到：`k8s-ebpf-1.0-SNAPSHOT.jar`、`tc_filter.bpf.o`、`update_map`、`config/`、`entrypoint.sh`
- `ls -la /home/appuser/agq/update_map /home/appuser/agq/entrypoint.sh` 具备可执行权限

### 1.4 一次性执行清单（在 VM 上执行）

按顺序复制执行：
1) `cd /home/appuser/agq`
2) `ls -la`
3) `sudo chmod +x update_map entrypoint.sh`
4) `ls -la update_map entrypoint.sh`

---

## 2. 环境检查与安装

### 2.1 检查命令

1) `uname -r`
2) `java -version`
3) `tc -V`

**验证点**
- `uname -r` 输出 5.x 或更高（低版本也可能可用，但不推荐）
- `java -version` 输出 1.8
- `tc -V` 能正常输出版本

### 2.3 一次性执行清单（在 VM 上执行）

按顺序复制执行：
1) `uname -r`
2) `java -version`
3) `tc -V`

### 2.2 安装依赖（按系统执行）

**Debian/Ubuntu**
1) `sudo apt-get update`
2) `sudo apt-get install -y openjdk-8-jre-headless iproute2`

**CentOS/RHEL/Rocky/Alma/Kylin V10**
1) `sudo yum install -y java-1.8.0-openjdk-headless iproute`

**SLES 12**
1) `sudo zypper install -y java-1_8_0-openjdk iproute2`

---

## 3. 启动程序（systemd）

### 3.1 创建服务文件

执行以下命令创建 `/etc/systemd/system/k8s-ebpf.service`：

`sudo tee /etc/systemd/system/k8s-ebpf.service >/dev/null <<'EOF'
[Unit]
Description=K8s eBPF Offcloud Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/appuser/agq
Environment=SIMPLIFIED_MODE=true
Environment=EBPF_AUTO_START=true
Environment=IFACE=enp3s0
Environment=CT_TIMEOUT_SECONDS=60
ExecStartPre=/bin/sh -c 'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf'
ExecStart=/home/appuser/agq/entrypoint.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF`

### 3.1.1 按步骤执行（逐条命令）

1) 设置网卡名变量（替换为你的网卡名）：
`IFACE=enp3s0`

2) 写入服务文件：
`sudo tee /etc/systemd/system/k8s-ebpf.service >/dev/null <<EOF
[Unit]
Description=K8s eBPF Offcloud Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/appuser/agq
Environment=SIMPLIFIED_MODE=true
Environment=EBPF_AUTO_START=true
Environment=IFACE=${IFACE}
Environment=CT_TIMEOUT_SECONDS=60
ExecStartPre=/bin/sh -c 'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf'
ExecStart=/home/appuser/agq/entrypoint.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF`

### 3.2 启动与验证

1) `sudo systemctl daemon-reload`
2) `sudo systemctl enable --now k8s-ebpf`
3) `systemctl status k8s-ebpf`
4) `curl -sS http://127.0.0.1:8080/actuator/health`

**验证点**
- `systemctl status k8s-ebpf` 显示 running
- `/actuator/health` 返回 UP

> 如果不使用 systemd，可直接执行：`sudo /home/appuser/agq/entrypoint.sh`

### 3.2.1 一次性执行清单（逐条命令）

1) `sudo systemctl daemon-reload`
2) `sudo systemctl enable --now k8s-ebpf`
3) `systemctl status k8s-ebpf`
4) `curl -sS http://127.0.0.1:8080/actuator/health`

---

## 4. eBPF 挂载与规则检查

### 4.1 挂载检查

1) `tc qdisc show dev enp3s0`
2) `tc filter show dev enp3s0 ingress`
3) `tc filter show dev enp3s0 egress`

**验证点**
- 看到 `clsact`
- ingress/egress 上有 bpf 过滤器

### 4.2 规则下发检查

1) `cd /home/appuser/agq`
2) `sudo ./update_map query | head -n 10`

**验证点**
- 能看到规则输出（为空表示尚未下发）

### 4.3 一次性执行清单（逐条命令）

1) `tc qdisc show dev enp3s0`
2) `tc filter show dev enp3s0 ingress`
3) `tc filter show dev enp3s0 egress`
4) `cd /home/appuser/agq`
5) `sudo ./update_map query | head -n 10`

---

## 5. 基线连通性检查

### 5.1 Nginx 基线

1) `curl -I http://82.19.116.227:8090`
2) 期望返回 200 或 302

### 5.2 应用健康基线

1) `curl -sS http://82.19.116.227:8080/actuator/health`
2) 期望返回 UP

### 5.3 一次性执行清单（逐条命令）

1) `curl -I http://82.19.116.227:8090`
2) `curl -sS http://82.19.116.227:8080/actuator/health`

---

## 6. 演示：出向管控（Egress）

### 6.1 下发阻断规则

`curl -sS -X POST http://127.0.0.1:8080/api/networkpolicy/add-rule \
  -H 'Content-Type: application/json' \
  -d '{
    "direction": "egress",
    "protocol": "TCP",
    "action": "deny",
    "port": 8090,
    "remoteIp": "82.19.116.227",
    "targetObject": {"type": "ip", "value": "82.19.116.227"}
  }'`

**验证点**
- `curl -I http://82.19.116.227:8090` 超时或失败

### 6.2 删除规则

`curl -sS -X POST http://127.0.0.1:8080/api/networkpolicy/delete-rule \
  -H 'Content-Type: application/json' \
  -d '{
    "direction": "egress",
    "protocol": "TCP",
    "port": 8090,
    "remoteIp": "82.19.116.227",
    "targetObject": {"type": "ip", "value": "82.19.116.227"}
  }'`

**验证点**
- `curl -I http://82.19.116.227:8090` 恢复成功

### 6.3 一次性执行清单（逐条命令）

1) `curl -sS -X POST http://127.0.0.1:8080/api/networkpolicy/add-rule \
  -H 'Content-Type: application/json' \
  -d '{
    "direction": "egress",
    "protocol": "TCP",
    "action": "deny",
    "port": 8090,
    "remoteIp": "82.19.116.227",
    "targetObject": {"type": "ip", "value": "82.19.116.227"}
  }'`
2) `curl -I http://82.19.116.227:8090`
3) `curl -sS -X POST http://127.0.0.1:8080/api/networkpolicy/delete-rule \
  -H 'Content-Type: application/json' \
  -d '{
    "direction": "egress",
    "protocol": "TCP",
    "port": 8090,
    "remoteIp": "82.19.116.227",
    "targetObject": {"type": "ip", "value": "82.19.116.227"}
  }'`
4) `curl -I http://82.19.116.227:8090`

---

## 7. 演示：入向管控（Ingress）

### 7.1 下发阻断规则

`curl -sS -X POST http://127.0.0.1:8080/api/networkpolicy/add-rule \
  -H 'Content-Type: application/json' \
  -d '{
    "direction": "ingress",
    "protocol": "TCP",
    "action": "deny",
    "port": 8080,
    "remoteIp": "0.0.0.0/0",
    "targetObject": {"type": "ip", "value": "82.19.116.227"}
  }'`

**验证点**
- `curl -sS http://82.19.116.227:8080/actuator/health` 失败

### 7.2 删除规则

`curl -sS -X POST http://127.0.0.1:8080/api/networkpolicy/delete-rule \
  -H 'Content-Type: application/json' \
  -d '{
    "direction": "ingress",
    "protocol": "TCP",
    "port": 8080,
    "remoteIp": "0.0.0.0/0",
    "targetObject": {"type": "ip", "value": "82.19.116.227"}
  }'`

**验证点**
- `curl -sS http://82.19.116.227:8080/actuator/health` 恢复成功

### 7.3 一次性执行清单（逐条命令）

1) `curl -sS -X POST http://127.0.0.1:8080/api/networkpolicy/add-rule \
  -H 'Content-Type: application/json' \
  -d '{
    "direction": "ingress",
    "protocol": "TCP",
    "action": "deny",
    "port": 8080,
    "remoteIp": "0.0.0.0/0",
    "targetObject": {"type": "ip", "value": "82.19.116.227"}
  }'`
2) `curl -sS http://82.19.116.227:8080/actuator/health`
3) `curl -sS -X POST http://127.0.0.1:8080/api/networkpolicy/delete-rule \
  -H 'Content-Type: application/json' \
  -d '{
    "direction": "ingress",
    "protocol": "TCP",
    "port": 8080,
    "remoteIp": "0.0.0.0/0",
    "targetObject": {"type": "ip", "value": "82.19.116.227"}
  }'`
4) `curl -sS http://82.19.116.227:8080/actuator/health`

---

## 8. 常见问题排查

1) 规则没生效
- 检查网卡是否正确
- 检查是否命中正确 IP/端口
- 检查是否在期望方向（ingress/egress）
- 通过 `./update_map query` 查看规则是否下发

2) 无法挂载 eBPF
- 内核版本不支持
- 权限不足（需 root）
- bpffs 未挂载（可手动执行 `mount -t bpf bpf /sys/fs/bpf`）

3) 健康检查失败
- 程序未启动或端口冲突
- `SIMPLIFIED_MODE` 未开启

---

## 9. 演示建议流程（固定模板）

1) 基线连通
2) 下发阻断规则
3) 验证阻断
4) 删除规则
5) 验证恢复
