//! IPC producer for the hook DLL - writes events to the launcher via shared memory.

use shared::{RingBufferHeader, SHM_NAME, SHM_SIZE};
use std::sync::atomic::Ordering;
use tracing_tunnel::TracingEvent;
use windows::core::PCWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Memory::*;

/// IPC producer that writes trace events to the launcher.
pub struct IpcProducer {
    ptr: *mut u8,
    handle: HANDLE,
}

// SAFETY: IpcProducer is moved into a Mutex for the tracing layer, which requires Send.
// The raw pointer and HANDLE are safely managed (opened/closed by this type) and Windows
// shared memory handles are safe to use from different threads.
unsafe impl Send for IpcProducer {}

impl IpcProducer {
    /// Open existing shared memory region created by the launcher.
    ///
    /// # Safety
    /// This function uses Windows APIs to open existing shared memory. The launcher must have
    /// created the shared memory region before this is called.
    pub unsafe fn open() -> Result<Self, String> {
        let name_wide: Vec<u16> = SHM_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = OpenFileMappingW(FILE_MAP_ALL_ACCESS.0, false, PCWSTR(name_wide.as_ptr()))
            .map_err(|e| format!("Failed to open file mapping: {}", e))?;

        if handle.is_invalid() {
            return Err("OpenFileMappingW returned invalid handle".to_string());
        }

        let ptr = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE).Value as *mut u8;

        if ptr.is_null() {
            let _ = CloseHandle(handle);
            return Err("MapViewOfFile failed".to_string());
        }

        // Validate we can access the header region
        let test_read = std::ptr::read_volatile(ptr as *const u8);
        let _ = test_read; // Suppress unused warning

        Ok(Self { ptr, handle })
    }

    /// Get the ring buffer header.
    unsafe fn header(&self) -> &RingBufferHeader {
        &*(self.ptr as *const RingBufferHeader)
    }

    /// Get the data region (after the header).
    unsafe fn data_ptr(&self) -> *mut u8 {
        self.ptr.add(std::mem::size_of::<RingBufferHeader>())
    }

    /// Write data to the ring buffer, handling wrap-around.
    unsafe fn write_bytes(&self, data_ptr: *mut u8, offset: usize, bytes: &[u8], capacity: usize) {
        let bytes_until_end = capacity - offset;
        if bytes.len() > bytes_until_end {
            // Split write: copy to end of buffer, then wrap to beginning
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr.add(offset), bytes_until_end);
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(bytes_until_end),
                data_ptr,
                bytes.len() - bytes_until_end,
            );
        } else {
            // Fits without wrapping
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr.add(offset), bytes.len());
        }
    }

    /// Write an event to the ring buffer.
    ///
    /// Returns true if the event was written, false if the buffer was full.
    pub fn write_event(&mut self, event: &TracingEvent) -> bool {
        unsafe {
            // Serialize event using serde_json
            let bytes = match serde_json::to_vec(event) {
                Ok(b) => b,
                Err(_) => return false,
            };

            let event_size = bytes.len();

            // Validate event size doesn't exceed maximum
            if event_size > shared::MAX_EVENT_SIZE {
                return false;
            }

            let total_size = 4 + event_size; // u32 size prefix + event data

            let header = self.header();
            let write_pos = header.write_pos.load(Ordering::SeqCst);
            let read_pos = header.read_pos.load(Ordering::SeqCst);
            let capacity = header.capacity as usize;

            // Check if there's enough space (simple check, may be conservative)
            let available = if write_pos >= read_pos {
                capacity - (write_pos - read_pos) as usize
            } else {
                (read_pos - write_pos) as usize
            };

            if available < total_size {
                return false; // Buffer full
            }

            let data_ptr = self.data_ptr();

            // Write size prefix, handling wrap-around
            let size_offset = write_pos as usize % capacity;
            let size_bytes = (event_size as u32).to_le_bytes();
            self.write_bytes(data_ptr, size_offset, &size_bytes, capacity);

            // Write event data, handling wrap-around
            let event_offset = (write_pos as usize + 4) % capacity;
            self.write_bytes(data_ptr, event_offset, &bytes, capacity);

            // Update write position with overflow check
            let new_write_pos = write_pos
                .checked_add(total_size as u32)
                .map(|pos| pos % (capacity as u32))
                .unwrap_or(0);

            header.write_pos.store(new_write_pos, Ordering::SeqCst);

            true
        }
    }
}

impl Drop for IpcProducer {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.ptr as *mut _,
            });
            let _ = CloseHandle(self.handle);
        }
    }
}
