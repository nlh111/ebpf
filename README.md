# ebpf

## How to build and run the eBPF program
### Android 14 Platform
1. Modify ./ebpf/hids/hids-ebpf/Cargo.toml default features to "vmlinux_android"
2.  export CC=xxxxx/aarch64-linux-android34-clang
3. cargo build --target=aarch64-linux-android --release

### ARM64 Linux Platform
1. Modify ./ebpf/hids/hids-ebpf/Cargo.toml default features to "vmlinux_armlinux"
2. export CC=xxxxx/aarch64-buildroot-linux-gnu-gcc
3. cargo build --target=aarch64-unknown-linux-gnu --release   