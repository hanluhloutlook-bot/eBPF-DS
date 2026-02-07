#!/bin/bash
set -e

# 配置信息
IMAGE_NAME="k8s-ebpf"
IMAGE_TAG="1.1.10"
# 以下根据你的环境修改：
# - 本地使用：REGISTRY="localhost" 或 "k8s-ebpf"
# - 私有仓库：REGISTRY="192.168.x.x:5000"
# - 国内镜像：REGISTRY="registry.cn-hangzhou.aliyuncs.com/你的命名空间"
# - 打包传输：REGISTRY="k8s-ebpf"（会生成tar文件）
REGISTRY="k8s-ebpf"

# 是否推送到远程仓库（true/false）
PUSH_TO_REMOTE=false

echo "🔍 验证文件是否存在..."
echo "当前目录: $(pwd)"
ls -la

# 验证必要文件
if [ ! -f "target/k8s-ebpf-1.0-SNAPSHOT.jar" ]; then
    echo "❌ 错误: target/k8s-ebpf-1.0-SNAPSHOT.jar 不存在!"
    echo "请确保已经编译了Java程序"
    exit 1
fi

if [ ! -f "tc_filter.bpf.o" ]; then
    echo "❌ 错误: tc_filter.bpf.o 不存在!"
    exit 1
fi

if [ ! -f "update_map" ]; then
    echo "❌ 错误: update_map 不存在!"
    exit 1
fi

if [ ! -x "update_map" ]; then
    echo "⚠️ 警告: update_map 没有执行权限，正在修复..."
    chmod +x update_map
fi

echo "✅ 所有必要文件验证通过"

echo "🐳 开始构建Docker镜像..."
echo "镜像名称: ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"

# 构建镜像
docker build \
    --tag ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} \
    --tag ${REGISTRY}/${IMAGE_NAME}:latest \
    .

echo "✅ Docker镜像构建完成!"

# 导出为tar文件（方便传输到其他机器）
echo "� 导出镜像为tar文件..."
docker save ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} > ${IMAGE_NAME}-${IMAGE_TAG}.tar
echo "✅ 镜像已导出为: ${IMAGE_NAME}-${IMAGE_TAG}.tar"

if [ "$PUSH_TO_REMOTE" = true ]; then
    echo "�📤 推送镜像到仓库..."
    # 登录镜像仓库（如果需要）
    # docker login ${REGISTRY}
    
    docker push ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
    docker push ${REGISTRY}/${IMAGE_NAME}:latest
    
    echo "✅ 镜像推送完成!"
else
    echo "💡 提示：推送到远程仓库已禁用，如需推送请将 PUSH_TO_REMOTE=true"
fi

# 显示镜像信息
echo ""
echo "📊 镜像信息:"
docker images | grep ${IMAGE_NAME}

echo ""
echo "📦 打包文件:"
ls -lh ${IMAGE_NAME}-${IMAGE_TAG}.tar
