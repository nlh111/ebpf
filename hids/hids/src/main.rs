use aya::{
    maps::{HashMap, Queue},
    programs::{BtfTracePoint},
    Btf,
};
use simplelog::{ConfigBuilder, LevelFilter, WriteLogger};
#[rustfmt::skip]
use log::{debug, warn, info};
use std::{collections::HashMap as StdHashMap, ffi::CString, fs::File, os::raw::c_char, ptr};

use hids_common::*;
use tokio::{
    self,
    time::{self, Duration},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_ebpf_program().await
}

#[no_mangle]
pub extern "C" fn start_ebpf_program() -> *mut c_char {
    let rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(run_ebpf_program()) {
        Ok(_) => ptr::null_mut(),
        Err(e) => {
            let err_msg = CString::new(format!("{}", e)).unwrap();
            err_msg.into_raw()
        }
    }
}

async fn run_ebpf_program() -> anyhow::Result<()> {
    WriteLogger::init(
        LevelFilter::Info,
        ConfigBuilder::new()
            .set_time_level(LevelFilter::Info)
            .build(),
        File::create("./hids.log")?,
    )?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/hids"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program_exec: &mut BtfTracePoint =
        ebpf.program_mut("sched_process_exec_func").unwrap().try_into()?;
    program_exec.load("sched_process_exec", &btf)?;
    program_exec.attach()?;

    let program_exit: &mut BtfTracePoint = ebpf
        .program_mut("sched_process_exit_func")
        .unwrap()
        .try_into()?;
    program_exit.load("sched_process_exit", &btf)?;
    program_exit.attach()?;


    let program_process_free: &mut BtfTracePoint = ebpf
        .program_mut("sched_process_free_func")
        .unwrap()
        .try_into()?;
    program_process_free.load("sched_process_free", &btf)?;
    program_process_free.attach()?;

    let mut interval = time::interval(Duration::from_millis(1000));

    let zombie_map = ebpf.take_map("zombie_processes").unwrap();
    let zombie_processes: HashMap<_, u32, ZombieEvent> = HashMap::try_from(&zombie_map)?;

    let mut root_processes: Queue<_, SuSudoEvent> =
        Queue::try_from(ebpf.map_mut("root_processes").unwrap())?;

    let mut zombie_counters: StdHashMap<u32, u32> = StdHashMap::new();
    let threshold = 5; // threshold for zombie process detection

    loop {
        interval.tick().await;

        // Print all events from the zombie_processes map
        let zombie_processes_size = zombie_processes.iter().count();
        info!("Zombie Processes Map size: {:?}", zombie_processes_size);
        for result in zombie_processes.iter() {
            match result {
                Ok((key, value)) => {
                    // Judge if the counter of the zombie process is greater than the threshold
                    if let Some(counter) = zombie_counters.get(&key) {
                        if *counter > threshold {
                            info!(
                                "Zombie process detected: pid: {}, comm: {:?}",
                                key,
                                String::from_utf8_lossy(&value.comm)
                                    .trim_end_matches('\0')
                                    .to_string()
                            );
                        }
                    }
                    let counter = zombie_counters.entry(key).or_insert(0);
                    *counter += 1;
                }
                Err(e) => {
                    info!("Error reading map: {:?}", e);
                }
            }
        }

        // Pop all events from the queue
        while let Ok(event) = root_processes.pop(0) {
            info!(
                "root process detect : pid: {}, comm: {:?}",
                event.pid,
                String::from_utf8_lossy(&event.comm)
                    .trim_end_matches('\0')
                    .to_string()
            );
        }
    }
}
