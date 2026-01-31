CLANG ?= clang
CC ?= gcc
BPF_CFLAGS = -O2 -target bpf -mcpu=v1 -D__TARGET_ARCH_x86

# 目标文件
BPF_OBJ := tc_filter.bpf.o tc_block_filter.bpf.o tc_egress_filter.bpf.o
LOADER  := loader

.PHONY: all clean check_libs

all: check_libs $(BPF_OBJ) $(LOADER)

# 检查依赖库是否存在
# 路径自动探测 (优先寻找静态库 .a 文件)
LIBBPF_A  := $(shell find /usr/lib64 /usr/lib /lib64 /lib -name "libbpf.a" 2>/dev/null | head -n 1)
LIBELF_A  := $(shell find /usr/lib64 /usr/lib /lib64 /lib -name "libelf.a" 2>/dev/null | head -n 1)
LIBZ_A    := $(shell find /usr/lib64 /usr/lib /lib64 /lib -name "libz.a" 2>/dev/null | head -n 1)

check_libs:
	@if [ -z "$(LIBBPF_A)" ]; then \
		echo "错误: 找不到 libbpf.a，请安装 libbpf-static 或 libbpf-devel"; \
		exit 1; \
	fi
	@if [ -z "$(LIBELF_A)" ]; then \
		echo "错误: 找不到 libelf.a，请安装 elfutils-libelf-devel"; \
		exit 1; \
	fi
	@if [ -z "$(LIBZ_A)" ]; then \
		echo "错误: 找不到 libz.a，请安装 zlib-static"; \
		exit 1; \
	fi
	

tc_filter.bpf.o: tc_filter.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	# 4.19 核心步骤：彻底移除 BTF 段，否则报 Invalid Argument 
	llvm-strip -g $@

tc_block_filter.bpf.o: tc_block_filter.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	# 4.19 核心步骤：彻底移除 BTF 段，否则报 Invalid Argument 
	llvm-strip -g $@

tc_egress_filter.bpf.o: tc_egress_filter.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	# 4.19 核心步骤：彻底移除 BTF 段，否则报 Invalid Argument 
	llvm-strip -g $@ 

$(LOADER): main.c
	$(CC) -O2 -Wall -o $@ $< \
			$(LIBBPF_A) \
			$(LIBELF_A) \
			$(LIBZ_A) \
			-static-libgcc -lpthread -ldl

clean:
	rm -f *.o loader