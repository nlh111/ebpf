#![no_std]
#![no_main]
#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[rustfmt::skip]
#[cfg(feature = "vmlinux_x86")]
mod vmlinux_x86;
#[cfg(feature = "vmlinux_x86")]
use vmlinux_x86::*;
#[cfg(feature = "vmlinux_armlinux")]
mod vmlinux_armlinux;
#[cfg(feature = "vmlinux_armlinux")]
use vmlinux_armlinux::*;
#[cfg(feature = "vmlinux_android")]
mod vmlinux_android;
use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{btf_tracepoint, map},
    maps::{HashMap, Queue},
    programs::BtfTracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use hids_common::*;
#[cfg(feature = "vmlinux_android")]
use vmlinux_android::*;

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec_func(ctx: BtfTracePointContext) -> i32 {
    match try_sched_process_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit_func(ctx: BtfTracePointContext) -> i32 {
    match try_sched_process_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

#[btf_tracepoint(function = "sched_process_free")]
pub fn sched_process_free_func(ctx: BtfTracePointContext) -> i32 {
    match try_sched_process_free(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

#[map(name = "root_processes")]
static mut ROOT_PROCESSES: Queue<SuSudoEvent> = Queue::with_max_entries(128, 0);

fn try_sched_process_exec(ctx: BtfTracePointContext) -> Result<i32, i32> {
    let comm = ctx.command().map_err(|e| e as i32)?;
    let pid = ctx.pid();
    unsafe {
        //let comm_str = core::str::from_utf8_unchecked(&comm);
        let null_pos = comm.iter().position(|&x| x == 0).unwrap_or(comm.len());
        let valid_comm = &comm[..null_pos];
        let comm_str = core::str::from_utf8_unchecked(valid_comm);

        // TODO: check if the process is running as root privilege
        let task: *const task_struct = ctx.arg(0);
        let cred: *const cred = match bpf_probe_read_kernel(&(*task).cred) {
            Ok(val) => val,
            Err(e) => {
                info!(&ctx, "Failed to read cred: {}", e);
                return Err(e as i32);
            }
        };
        let uid: u32 = match bpf_probe_read_kernel(&(*cred).uid.val) {
            Ok(val) => val,
            Err(e) => {
                info!(&ctx, "Failed to read uid: {}", e);
                return Err(e as i32);
            }
        };
        let euid: u32 = match bpf_probe_read_kernel(&(*cred).euid.val) {
            Ok(val) => val,
            Err(e) => {
                info!(&ctx, "Failed to read euid: {}", e);
                return Err(e as i32);
            }
        };
        let suid: u32 = match bpf_probe_read_kernel(&(*cred).suid.val) {
            Ok(val) => val,
            Err(e) => {
                info!(&ctx, "Failed to read suid: {}", e);
                return Err(e as i32);
            }
        };
        info!(
            &ctx,
            "process exec, pid: {}, comm: {}, uid: {}, euid: {}, suid: {}",
            pid,
            comm_str,
            uid,
            euid,
            suid
        );

        let mut is_root_elevated: bool = false;
        if uid != euid && suid == 0 {
            is_root_elevated = true;
        }

        if contains(comm_str, "su") || is_root_elevated {
            info!(
                &ctx,
                "root process detect pid: {},  comm: {}", pid, comm_str
            );
            // push the event to the queue
            ROOT_PROCESSES
                .push(
                    &SuSudoEvent {
                        pid: pid,
                        comm: comm,
                    },
                    0,
                )
                .map_err(|e| e as i32)?;
        } else {
            // do nothing
        }
    }
    Ok(0)
}

#[map(name = "zombie_processes")]
static mut ZOMBIE_PROCESSES: HashMap<u32, ZombieEvent> = HashMap::with_max_entries(1024, 0);

fn try_sched_process_exit(ctx: BtfTracePointContext) -> Result<i32, i32> {
    unsafe {
        let task: *const task_struct = ctx.arg(0);

        let real_parent: *const task_struct = match bpf_probe_read_kernel(&(*task).real_parent) {
            Ok(val) => val,
            Err(e) => {
                info!(&ctx, "Failed to read real_parent: {}", e);
                return Err(e as i32);
            }
        };

        let parent_pid: i32 = match bpf_probe_read_kernel(&(*real_parent).pid) {
            Ok(val) => val,
            Err(e) => {
                info!(&ctx, "Failed to read parent_pid: {}", e);
                return Err(e as i32);
            }
        };

        let pid: u32 = ctx.pid();
        let comm = ctx.command().map_err(|e| e as i32)?;
        ZOMBIE_PROCESSES
            .insert(
                &pid,
                &ZombieEvent {
                    pid: pid,
                    comm: comm,
                },
                0,
            )
            .map_err(|e| e as i32)?;
        info!(
            &ctx,
            "process exit, pid: {}, parent_pid: {}", pid, parent_pid
        );
    }
    Ok(0)
}

fn try_sched_process_free(ctx: BtfTracePointContext) -> Result<i32, i32> {
    unsafe {
        let task: *const task_struct = ctx.arg(0);
        if task.is_null() {
            info!(&ctx, "Invalid task pointer in function sched_process_free");
            return Err(1);
        }
        let pid: u32 = match bpf_probe_read_kernel(&(*task).pid) {
            Ok(val) => val as u32,
            Err(e) => {
                info!(&ctx, "Failed to read pid: {}", e);
                return Err(e as i32);
            }
        };
        match ZOMBIE_PROCESSES.remove(&pid) {
            Ok(_) => info!(
                &ctx,
                "Successfully removed pid: {} from ZOMBIE_PROCESSES", pid
            ),
            Err(e) => info!(
                &ctx,
                "Failed to remove pid: {} from ZOMBIE_PROCESSES, error: {}", pid, e
            ),
        }

        info!(&ctx, "Freeing process, pid: {}", pid);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
