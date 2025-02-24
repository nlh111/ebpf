#include <stdio.h>
extern char* start_ebpf_program();
int main() {
    start_ebpf_program();
    return 0;
}