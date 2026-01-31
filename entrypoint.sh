#!/bin/bash
set -euo pipefail

echo "================================================"
echo "Starting eBPF Java Application"
echo "Node: ${NODE_NAME:-unknown}"
echo "Pod IP: ${POD_IP:-unknown}"
echo "================================================"

# 创建日志目录
mkdir -p /var/log/app

# 设置内核参数
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# 验证eBPF文件存在
if [ -f "/app/tc_filter.bpf.o" ]; then
    echo "✅ eBPF object file found: /app/tc_filter.bpf.o"
    echo "   File size: $(stat -c%s /app/tc_filter.bpf.o) bytes"
    
    # 验证eBPF文件格式
    if command -v readelf >/dev/null 2>&1; then
        echo "   eBPF file type: $(readelf -h /app/tc_filter.bpf.o | grep Type | awk '{print $2}')"
    fi
else
    echo " eBPF object file not found!"
fi

# 自动加载并挂载 eBPF（默认开启，确保覆盖所有工作负载流量路径）
EBPF_AUTO_START=${EBPF_AUTO_START:-true}
EBPF_INTERFACE=${EBPF_INTERFACE:-${IFACE:-eth0}}
if [ "$EBPF_AUTO_START" = "true" ]; then
    echo "Auto start eBPF on interface: ${EBPF_INTERFACE}"
    /app/update_map start "${EBPF_INTERFACE}" || echo "⚠️ eBPF auto start failed (continuing)"
else
    echo "EBPF_AUTO_START=false, skip eBPF attach"
fi

# 启动Java应用
echo " Starting Java application..."
echo "Java version: $(java -version 2>&1 | head -1)"
echo "JVM options: ${JAVA_OPTS:--Xms256m -Xmx512m}"

exec java ${JAVA_OPTS:--Xms256m -Xmx512m} \
    -Djava.security.egd=file:/dev/./urandom \
    -Dbpf.object.path=/app/tc_filter.bpf.o \
    -jar /app/k8s-ebpf-1.0-SNAPSHOT.jar \
    --spring.config.location=/app/config/application.properties