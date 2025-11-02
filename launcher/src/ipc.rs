//! IPC consumer for the launcher process - reads events from the hook DLL via shared memory.

use shared::{RingBufferHeader, RING_BUFFER_SIZE, SHM_NAME, SHM_SIZE};
use std::sync::atomic::Ordering;
use tracing::{debug, error, warn};
use tracing_tunnel::{TracingEvent, TracingEventReceiver};
use windows::core::PCWSTR;
use windows::Win32::Foundation::*;
use windows::Win32::System::Memory::{CreateFileMappingW, *};

/// IPC consumer that reads trace events from the hook DLL.
pub struct IpcConsumer {
    ptr: *mut u8,
    handle: HANDLE,
}

// SAFETY: IpcConsumer is moved into the IPC polling thread, which requires Send.
// The raw pointer and HANDLE are safely managed (created/closed by this type) and Windows
// shared memory handles are safe to use from different threads.
unsafe impl Send for IpcConsumer {}

impl IpcConsumer {
    /// Create a new IPC consumer, initializing the shared memory region.
    ///
    /// # Safety
    /// This function uses Windows APIs to create named shared memory. The caller must ensure
    /// that only one consumer exists per shared memory region.
    pub unsafe fn new() -> Result<Self, String> {
        debug!(
            name = SHM_NAME,
            size = SHM_SIZE,
            "Creating shared memory region"
        );

        let name_wide: Vec<u16> = SHM_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,
            PAGE_READWRITE,
            0,
            SHM_SIZE as u32,
            PCWSTR(name_wide.as_ptr()),
        )
        .map_err(|e| format!("Failed to create file mapping: {}", e))?;

        if handle.is_invalid() {
            return Err("CreateFileMappingW returned invalid handle".to_string());
        }

        let ptr = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE).Value as *mut u8;

        if ptr.is_null() {
            let _ = CloseHandle(handle);
            return Err("MapViewOfFile failed".to_string());
        }

        // Validate we can access the full memory region
        std::ptr::write_bytes(ptr, 0, std::mem::size_of::<RingBufferHeader>());

        // Initialize ring buffer header at the start of shared memory
        let header = ptr as *mut RingBufferHeader;
        (*header).write_pos.store(0, Ordering::SeqCst);
        (*header).read_pos.store(0, Ordering::SeqCst);
        (*header).capacity = RING_BUFFER_SIZE as u32;

        debug!("IPC initialized");

        Ok(Self { ptr, handle })
    }

    /// Get the ring buffer header.
    unsafe fn header(&self) -> &RingBufferHeader {
        &*(self.ptr as *const RingBufferHeader)
    }

    /// Get the data region (after the header).
    unsafe fn data_ptr(&self) -> *const u8 {
        self.ptr.add(std::mem::size_of::<RingBufferHeader>())
    }

    /// Read data from the ring buffer, handling wrap-around.
    unsafe fn read_bytes(
        &self,
        data_ptr: *const u8,
        offset: usize,
        buffer: &mut [u8],
        capacity: usize,
    ) {
        let bytes_until_end = capacity - offset;
        if buffer.len() > bytes_until_end {
            // Split read: read from end of buffer, then wrap to beginning
            std::ptr::copy_nonoverlapping(
                data_ptr.add(offset),
                buffer.as_mut_ptr(),
                bytes_until_end,
            );
            std::ptr::copy_nonoverlapping(
                data_ptr,
                buffer.as_mut_ptr().add(bytes_until_end),
                buffer.len() - bytes_until_end,
            );
        } else {
            // Fits without wrapping
            std::ptr::copy_nonoverlapping(data_ptr.add(offset), buffer.as_mut_ptr(), buffer.len());
        }
    }

    /// Poll for a single event, returning None if the buffer is empty.
    pub fn poll_event(&mut self) -> Option<TracingEvent> {
        unsafe {
            let header = self.header();
            let read_pos = header.read_pos.load(Ordering::SeqCst);
            let write_pos = header.write_pos.load(Ordering::SeqCst);

            if read_pos == write_pos {
                return None; // Buffer empty
            }

            let data_ptr = self.data_ptr();
            let capacity = header.capacity as usize;

            // Read event size (u32), handling wrap-around
            let size_offset = read_pos as usize % capacity;
            let mut size_bytes = [0u8; 4];
            self.read_bytes(data_ptr, size_offset, &mut size_bytes, capacity);
            let event_size = u32::from_le_bytes(size_bytes) as usize;

            // Validate event size before allocation
            if event_size == 0 || event_size > shared::MAX_EVENT_SIZE {
                error!(size = event_size, "Invalid event size, skipping");
                // Skip this corrupted event
                let skip_pos = read_pos.checked_add(4).unwrap_or(0) % (capacity as u32);
                header.read_pos.store(skip_pos, Ordering::SeqCst);
                return None;
            }

            // Read event data, handling wrap-around
            let event_offset = (read_pos as usize + 4) % capacity;
            let mut event_bytes = vec![0u8; event_size];
            self.read_bytes(data_ptr, event_offset, &mut event_bytes, capacity);

            // Deserialize using serde_json
            let event = match serde_json::from_slice::<TracingEvent>(&event_bytes) {
                Ok(ev) => Some(ev),
                Err(e) => {
                    error!(error = ?e, "Failed to deserialize event");
                    None
                }
            };

            // Update read position with overflow check
            let new_read_pos = read_pos
                .checked_add(4 + event_size as u32)
                .map(|pos| pos % (capacity as u32))
                .unwrap_or(0);

            header.read_pos.store(new_read_pos, Ordering::SeqCst);

            event
        }
    }

    /// Poll for all available events, returning them as a Vec.
    pub fn poll_all_events(&mut self) -> Vec<TracingEvent> {
        let mut events = Vec::new();
        while let Some(event) = self.poll_event() {
            events.push(event);
        }
        events
    }
}

impl Drop for IpcConsumer {
    fn drop(&mut self) {
        unsafe {
            let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.ptr as *mut _,
            });
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Process trace events from IPC and forward them to the local tracing subscriber.
/// Uses TracingEventReceiver to replay events with full fidelity.
pub fn process_events(consumer: &mut IpcConsumer, receiver: &mut TracingEventReceiver) {
    for event in consumer.poll_all_events() {
        if let Err(err) = receiver.try_receive(event) {
            warn!(%err, "Received invalid tracing event from hook");
        }
    }
}
