# Build image requirements
BUILD_IMAGE ?= syscall-recorder-build:latest
RUNTIME ?= podman

# Binary requirements
BPFTOOL ?= bpftool
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
STRIP ?= strip

# Build paths
OUT := build
BINARY := syscallrecorder

# Build flags
ARCH := $(shell uname -m | \
	sed 's/x86_64/x86/' | \
	sed 's/aarch64/arm64/' | \
	sed 's/ppc64le/powerpc/' | \
	sed 's/mips.*/mips/')
CFLAGS ?= -g -O2 -Wall
LDFLAGS ?= -lelf -lz -lbpf -lseccomp
INCLUDES := -I$(OUT)

.PHONY: all
all: $(OUT)/$(BINARY)

.PHONY: clean
clean:
	rm -rf $(OUT)

.PHONY: build-image
build-image:
	$(RUNTIME) build -t $(BUILD_IMAGE) hack/build

define run-in-container
	$(RUNTIME) run -it -v $(shell pwd):/work -w /work $(BUILD_IMAGE) $(1)
endef

.PHONY: build-in-container
build-in-container: build-image
	$(call run-in-container,make)

.PHONY: build-in-container-static
build-in-container-static: build-image
	$(call run-in-container,make static)

.PHONY: static
static:
	make all LDFLAGS='\
		-static \
		/usr/lib64/libbpf.a \
		/usr/lib64/libz.a \
		/usr/lib64/libseccomp.a \
		/usr/lib64/libelf.a'

$(OUT):
	mkdir -p $@

$(OUT)/$(BINARY): %: %.o | $(OUT)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@
	$(STRIP) -s $@

$(patsubst %,$(OUT)/%.o,$(BINARY)): %.o: %.skel.h

$(OUT)/%.o: %.c $(wildcard %.h) | $(OUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUT)/%.skel.h: $(OUT)/%.bpf.o | $(OUT)
	$(BPFTOOL) gen skeleton $< > $@

$(OUT)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUT)/%.bpf.o: %.bpf.c $(wildcard %.h) $(OUT)/vmlinux.h | $(OUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		$(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@

.PHONY: hook
hook:
	cd hack/oci-hook && go build hook.go

.PHONY: vagrant
vagrant: build-in-container-static
	vagrant up
