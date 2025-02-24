# Set CMake for cross-compiling
set(CMAKE_CONTROL_NAME ADD)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(tools "/home/xm/aarch64--glibc--stable-2022.03-1")
set(CMAKE_ASM_COMPILER  "${tools}/bin/aarch64-buildroot-linux-gnu-as")
set(CMAKE_C_COMPILER   "${tools}/bin/aarch64-buildroot-linux-gnu-gcc")
set(CMAKE_AR           "${tools}/bin/aarch64-buildroot-linux-gnu-ar")
set(CMAKE_RANLIB       "${tools}/bin/aarch64-buildroot-linux-gnu-ranlib")
set(CMAKE_LINKER       "${tools}/bin/aarch64-buildroot-linux-gnu-ld")
set(CMAKE_STRIP "${tools}/bin/aarch64-buildroot-linux-gnu-strip")



