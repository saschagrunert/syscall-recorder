FROM registry.fedoraproject.org/fedora:34

RUN dnf install -y \
    bpftool \
    clang \
    cpio \
    glibc-static \
    libbpf-devel \
    libbpf-static \
    libseccomp-devel \
    libseccomp-static \
    llvm \
    wget \
    zlib-static

# Fetch an older centos version because the static lib is gone from Fedora 34
RUN wget http://mirror.centos.org/centos/7/os/x86_64/Packages/elfutils-libelf-devel-static-0.176-5.el7.x86_64.rpm && \
    rpm2cpio elfutils-libelf-devel-static-0.176-5.el7.x86_64.rpm | cpio -idmv
