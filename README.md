# ebpf
## Introduction
This project use rust ayas to build eBPF program. The eBPF program is used to monitor the su or sudo command and zombie 
process.

## How to build and run the eBPF program
### Android 14 Platform
1. Modify ./ebpf/hids/hids-ebpf/Cargo.toml default features to "vmlinux_android"
2.  export CC=xxxxx/aarch64-linux-android34-clang
3. cargo build --target=aarch64-linux-android --release

### ARM64 Linux Platform
1. Modify ./ebpf/hids/hids-ebpf/Cargo.toml default features to "vmlinux_armlinux"
2. export CC=xxxxx/aarch64-buildroot-linux-gnu-gcc
3. cargo build --target=aarch64-unknown-linux-gnu --release 

### x86_64 Linux Platform
1. Modify ./ebpf/hids/hids-ebpf/Cargo.toml default features to "vmlinux_x86"
2. cargo run --release --config 'target."cfg(all())".runner="sudo -E"'  