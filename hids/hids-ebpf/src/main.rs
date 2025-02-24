#![no_std]
#![no_main]

use aya_ebpf::{macros::btf_tracepoint, programs::BtfTracePointContext};
use aya_log_ebpf::info;

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    match try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_exec(ctx: BtfTracePointContext) -> Result<i32, i32> {
    info!(&ctx, "tracepoint sched_process_exec called");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
