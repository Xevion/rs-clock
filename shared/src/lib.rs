//! Shared constants for rs-clock hook and launcher communication.

use std::sync::atomic::AtomicU32;

/// Shared memory region identifier.
/// Using Local\ namespace to avoid requiring administrator privileges.
pub const SHM_NAME: &str = "Local\\rs-clock-ipc";

/// Named event for hook readiness synchronization.
/// Using Local\ namespace to avoid requiring administrator privileges.
pub const READY_EVENT_NAME: &str = "Local\\rs-clock-hook-ready";

/// Size of the shared memory region (64KB).
pub const SHM_SIZE: usize = 64 * 1024;

/// Size of the ring buffer header with alignment padding.
/// RingBufferHeader is 12 bytes but aligned to 16 bytes in practice.
pub const HEADER_SIZE: usize = 16;

/// Size of the ring buffer within shared memory (after header).
pub const RING_BUFFER_SIZE: usize = SHM_SIZE - HEADER_SIZE;

/// SPSC ring buffer header in shared memory.
/// This structure is placed at the start of the shared memory region.
#[repr(C)]
pub struct RingBufferHeader {
    pub write_pos: AtomicU32,
    pub read_pos: AtomicU32,
    pub capacity: u32,
}
