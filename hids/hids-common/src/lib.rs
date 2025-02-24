#![no_std]

const TASK_COMM_LEN: usize = 16; // Task Command Length

// root process struct
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SuSudoEvent {
    pub pid: u32,                  // Process ID
    pub comm: [u8; TASK_COMM_LEN], // Command String
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SuSudoEvent {}

// ZOMBIE process struct
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ZombieEvent {
    pub pid: u32,                  // Process ID
    pub comm: [u8; TASK_COMM_LEN], // Command String
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ZombieEvent {}

pub fn contains(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}
