//! Tracing subscriber that forwards events to the launcher via IPC using tracing-tunnel.

use crate::ipc::IpcProducer;
use std::sync::Mutex;
use tracing::Subscriber;
use tracing_tunnel::TracingEventSender;

/// Create a tracing subscriber that forwards events to the launcher process via shared memory.
///
/// # Safety
/// Must be called after the launcher has created the shared memory region.
pub unsafe fn create_ipc_subscriber() -> Result<impl Subscriber, String> {
    // Open the IPC producer
    let producer = IpcProducer::open()?;
    let producer = Mutex::new(producer);

    // Create a TracingEventSender that sends events via IPC
    let subscriber = TracingEventSender::new(move |event| {
        if let Ok(mut guard) = producer.lock() {
            if !guard.write_event(&event) {
                // Buffer full - event was dropped
                // Use eprintln instead of tracing to avoid recursion
                eprintln!("Warning: IPC ring buffer full, event dropped");
            }
        }
    });

    Ok(subscriber)
}
