ARG JRE_BASE_IMAGE=registry.cn-hangzhou.aliyuncs.com/dragonwell/dragonwell:8
ARG BUILD_BASE_IMAGE=kindest/node:v1.28.6
ARG RUNTIME_BASE_IMAGE=kindest/node:v1.28.6

FROM ${JRE_BASE_IMAGE} AS jre

FROM ${BUILD_BASE_IMAGE} AS update-map-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        llvm \
        libbpf-dev \
        libelf-dev \
        linux-libc-dev \
        zlib1g-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY update_map.c tc_filter.bpf.c vmlinux.h policy.h /src/
RUN cc -O2 -g update_map.c -o update_map -lbpf -lelf -lz
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c tc_filter.bpf.c -o tc_filter.bpf.o

FROM ${RUNTIME_BASE_IMAGE}

USER root

# 从 Dragonwell 基础镜像拷贝 JRE 到运行镜像（运行镜像已内置 tc/curl 等工具）
COPY --from=jre /opt/alibaba/dragonwell8 /opt/dragonwell8

ENV JAVA_HOME=/opt/dragonwell8
ENV PATH="${JAVA_HOME}/bin:${PATH}"

WORKDIR /app

COPY target/k8s-ebpf-1.0-SNAPSHOT.jar /app/
COPY --from=update-map-builder /src/tc_filter.bpf.o /app/
COPY --from=update-map-builder /src/update_map /app/
COPY config/ /app/config/

RUN chmod +x /app/update_map

ENV BPF_OBJECT_PATH=/app/tc_filter.bpf.o

RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
