ARG JRE_BASE_IMAGE=eclipse-temurin:8-jre
ARG BUILD_BASE_IMAGE=debian:bookworm-slim
ARG RUNTIME_BASE_IMAGE=debian:bookworm-slim

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
RUN cc -O2 -static -s update_map.c -o update_map -lbpf -lelf -lz
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c tc_filter.bpf.c -o tc_filter.bpf.o

FROM ${RUNTIME_BASE_IMAGE}

USER root

RUN apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=20 update \
    && apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=20 install -y --no-install-recommends --fix-missing \
        ca-certificates \
        curl \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# 从 Temurin 基础镜像拷贝 JRE 到运行镜像
COPY --from=jre /opt/java/openjdk /opt/java/openjdk

ENV JAVA_HOME=/opt/java/openjdk
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
