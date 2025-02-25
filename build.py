import toml
import os
import sys
from colorama import init, Fore, Style

# initialize colorama
init()

# function: print success message
def print_success(msg):
    print(f"{Fore.GREEN}{Style.BRIGHT}✔ {msg}{Style.RESET_ALL}")

# function: print error message
def print_error(msg):
    print(f"{Fore.RED}{Style.BRIGHT}✘ {msg}{Style.RESET_ALL}")

# function: print info message
def print_info(msg):
    print(f"{Fore.BLUE}{Style.BRIGHT}ℹ {msg}{Style.RESET_ALL}")

# function: modify cargo.toml to build ebpf programs
def modify_cargo_toml(domain):
    toml_file_path = "/home/xm/ebpf/hids/hids-ebpf/Cargo.toml"
    with open(toml_file_path, "r") as f:
        data = toml.load(f)
    if domain == "add":
        feature = "vmlinux_armlinux"
    elif domain == "xcd":
        feature = "vmlinux_android"
    elif domain == "x86":
        feature = "vmlinux_x86"
    else:
        print_error("Error: invalid domain")
        return
    # modify Cargo.toml
    if 'features' in data and 'default' in data['features']:
        data['features']['default'] = [feature]
    else:
        print_error("Error: features.default not found in Cargo.toml")
        return
    
    # write to Cargo.toml
    with open(toml_file_path, "w") as f:
        toml.dump(data, f)
        print_success("Cargo.toml modified successfully")

# function: build ebpf programs
def build_ebpf_programs(domain, is_debug=False):
    if domain == "add":
        modify_cargo_toml("add")
    elif domain == "xcd":
        modify_cargo_toml("xcd")
    elif domain == "x86":
        modify_cargo_toml("x86")
    else:
        print_error("Error: invalid domain")
        return
    # build ebpf programs
    # cd the directory
    os.chdir("./hids")
    # build ebpf programs
    if domain == "add":
        # unset the CC variable
        os.system("unset CC")
        # export the CC variable
        os.system("export CC=/home/xm/aarch64--glibc--stable-2022.03-1/bin/aarch64-buildroot-linux-gnu-gcc")
        if is_debug:
            os.system("cargo build --target=aarch64-unknown-linux-gnu --quiet")
        else:
            os.system("cargo build --target=aarch64-unknown-linux-gnu --release --quiet")
    elif domain == "xcd":
        # unset the CC variable
        os.system("unset CC")
        # export the CC variable
        os.system("export CC=/home/xm/android-ndk-r26b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang")
        if is_debug:
            os.system("cargo build --target=aarch64-linux-android --quiet")
        else:
            os.system("cargo build --target=aarch64-linux-android --release --quiet")
    elif domain == "x86":
        os.system("unset CC")
        if is_debug:
            os.system("cargo run --config 'target.\"cfg(all())\".runner=\"sudo -E\"' ")
        else:
            os.system("cargo run --release --config 'target.\"cfg(all())\".runner=\"sudo -E\"' ")
    else:
        print_error("Error: invalid domain")
        return
    print_success("ebpf programs built successfully")
    os.chdir("..")

# function: build c programs
def build_c_programs(domain):
    os.chdir("./c_code")
    # delete the build directory
    os.system("rm -rf build")
    # create the build directory
    os.system("mkdir build")
    # cd the build directory
    os.chdir("./build")
    # unset the CC variable
    os.system("unset CC")
    # build c programs
    if domain == "add":
        os.system("cmake .. --toolchain ../arm_linux.cmake")
        os.system("cmake --build .")
    elif domain == "xcd":
        os.system("cmake .. --toolchain ../arm_android.cmake")
        os.system("cmake --build .")
    elif domain == "x86":
        os.system("cmake .. --toolchain ../x86_linux.cmake")
        os.system("cmake --build .")
    else:
        print_error("Error: invalid domain")
        return
    print_success("c programs built successfully")

# main function
if __name__ == "__main__":
    print_info("Please input the domain you want to build: 1. ADD 2. XCD 3. X86")
    user_input = input()
    if user_input == "1":
        domain = "add"
    elif user_input == "2":
        domain = "xcd"
    elif user_input == "3":
        domain = "x86"
    else:
        domain = None

    if domain:
        print_info("Do you want to build in debug mode? (y/n)")
        is_debug = input()
        if is_debug == "y":
            is_debug = True
        else:
            is_debug = False
        build_ebpf_programs(domain, is_debug)
        build_c_programs(domain)
    else:
        print_error("Error: invalid domain")
        sys.exit(1)