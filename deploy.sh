#!/bin/bash
set -e

# 配置信息
IMAGE_NAME="k8s-ebpf"
IMAGE_TAG="1.1.8"
# 以下根据你的环境修改：
# - 本地使用：REGISTRY="localhost" 或 "k8s-ebpf"
# - 私有仓库：REGISTRY="192.168.x.x:5000"
# - 国内镜像：REGISTRY="registry.cn-hangzhou.aliyuncs.com/你的命名空间"
# - 打包传输：REGISTRY="k8s-ebpf"
REGISTRY="k8s-ebpf"

echo "🚀 开始部署 k8s-ebpf DaemonSet..."

# 1. 更新DaemonSet配置中的镜像地址
echo "📝 更新镜像地址..."
sed -E -i.bak "s|k8s-ebpf/k8s-ebpf:[0-9.]+|${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}|g" daemonset.yaml

echo "✅ 镜像地址更新为: ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"

# 2. 检查Kubernetes连接
echo "🔍 检查Kubernetes集群连接..."
kubectl cluster-info
if [ $? -ne 0 ]; then
    echo "❌ 无法连接到Kubernetes集群"
    exit 1
fi

echo "✅ Kubernetes集群连接正常"

# 3. 创建命名空间（如果不存在）
echo "📦 创建/验证命名空间..."
kubectl get namespace kube-system > /dev/null 2>&1 || kubectl create namespace kube-system

# 4. 应用DaemonSet
echo "📤 部署DaemonSet..."
kubectl apply -f daemonset.yaml

# 5. 等待Pod创建
echo "⏳ 等待Pod创建..."
sleep 10

# 6. 检查部署状态
echo "📊 检查部署状态..."
echo ""
echo "1. DaemonSet状态:"
kubectl get daemonset -n kube-system k8s-ebpf-daemonset -o wide

echo ""
echo "2. Pod分布:"
kubectl get pods -n kube-system -l app=k8s-ebpf -o wide

echo ""
echo "3. Pod详细状态:"
kubectl describe daemonset -n kube-system k8s-ebpf-daemonset

# 7. 检查日志
echo ""
echo "📝 检查Pod日志:"
POD_NAME=$(kubectl get pods -n kube-system -l app=k8s-ebpf -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -n "$POD_NAME" ]; then
    echo "第一个Pod的名称: $POD_NAME"
    echo "最近20条日志:"
    kubectl logs -n kube-system $POD_NAME --tail=20
else
    echo "⚠️ 尚未找到运行的Pod"
fi

# 8. 验证所有节点都有Pod运行
echo ""
echo "🔍 验证节点覆盖:"
NODE_COUNT=$(kubectl get nodes --no-headers | wc -l)
POD_COUNT=$(kubectl get pods -n kube-system -l app=k8s-ebpf --no-headers | wc -l)

echo "集群节点数: $NODE_COUNT"
echo "运行Pod数: $POD_COUNT"

if [ "$NODE_COUNT" -eq "$POD_COUNT" ]; then
    echo "✅ 所有节点都有Pod运行"
else
    echo "⚠️ 警告: 不是所有节点都有Pod运行"
    echo "  节点列表:"
    kubectl get nodes -o name
    echo ""
    echo "  Pod分布:"
    kubectl get pods -n kube-system -l app=k8s-ebpf -o wide --no-headers | awk '{print "  " $1 " -> " $7}'
fi

echo ""
echo "✅ 部署完成!"
echo ""
echo "📋 后续操作:"
echo "1. 查看所有Pod日志: kubectl logs -n kube-system -l app=k8s-ebpf --tail=50"
echo "2. 进入Pod调试: kubectl exec -it -n kube-system <pod-name> -- bash"
echo "3. 删除部署: kubectl delete -f daemonset.yaml"
echo "4. 更新镜像: 修改IMAGE_TAG后重新运行 ./build.sh 和 ./deploy.sh"

# 恢复备份文件
mv daemonset.yaml.bak daemonset.yaml 2>/dev/null || true
