# syscall-recorder

## Requirements

### Build time

- [bpftool][bpftool]
- [clang][clang]
- [libbpf][libbpf]
- [libelf][libelf]
- [libseccomp][libseccomp] (for converting the syscall IDs to names)
- [libz][libz]
- [llvm][llvm] (`llvm-strip`)

### Build procedure

Running make invokes a series of commands to build the application:

1. Creates a `vmlinux.h` via `bpftool btf dump file`
1. Builds the ebpf application object via `clang -target bpf`
1. Strips the object via `llvm-strip`
1. Generate the skeleton (`.skel.h`) from the object via `bpftool gen skeleton`
1. Compile the application by using the skeleton and link the required libs

### Runtime

- [libbpf][libbpf]
- [libelf][libelf]
- [libseccomp][libseccomp]
- [libz][libz]

[bpftool]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/bpf/bpftool
[clang]: https://clang.llvm.org
[libbpf]: https://github.com/libbpf/libbpf
[libelf]: https://sourceware.org/elfutils
[libseccomp]: https://github.com/seccomp/libseccomp
[libz]: https://zlib.net
[llvm]: https://llvm.org
