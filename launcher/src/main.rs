//! Launcher that injects the hook DLL into Explorer.exe to customize the Windows clock.

mod ipc;

use std::ffi::OsStr;
use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, Level};
use tracing_subscriber::fmt::time::FormatTime;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Threading::*;
use windows::Win32::UI::WindowsAndMessaging::*;

/// Custom timer that formats uptime with millisecond precision (3 decimal places).
struct MillisTimer {
    start: Instant,
}

impl MillisTimer {
    fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl FormatTime for MillisTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
        let elapsed = self.start.elapsed();
        let secs = elapsed.as_secs_f64();
        write!(w, "{:8.3}s", secs)
    }
}

type InstallHookFn = unsafe extern "system" fn(u32) -> BOOL;
type RemoveHookFn = unsafe extern "system" fn() -> BOOL;

fn main() {
    tracing_subscriber::fmt()
        .with_level(true)
        .with_timer(MillisTimer::new())
        .with_max_level(Level::DEBUG)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        git_commit = env!("GIT_HASH"),
        built_at = env!("BUILD_TIMESTAMP"),
        "rs-clock"
    );

    // Initialize IPC consumer for receiving hook events
    let mut ipc_consumer = unsafe {
        match ipc::IpcConsumer::new() {
            Ok(consumer) => consumer,
            Err(e) => {
                error!(error = %e, "Failed to create IPC consumer");
                return;
            }
        }
    };

    unsafe {
        let taskbar = match find_taskbar() {
            Some(hwnd) => hwnd,
            None => {
                error!("Failed to locate taskbar window");
                return;
            }
        };

        let (explorer_thread_id, _explorer_process_id) = match get_explorer_info(taskbar) {
            Some(info) => {
                debug!(
                    thread_id = format_args!("0x{:08x}", info.0),
                    process_id = format_args!("0x{:08x}", info.1),
                    "Retrieved Explorer identifiers"
                );
                info
            }
            None => {
                error!("Failed to retrieve Explorer thread information");
                return;
            }
        };

        let dll_handle = match load_hook_dll() {
            Ok(handle) => handle,
            Err(e) => {
                error!(error = %e, "Failed to load hook library");
                return;
            }
        };

        let (install_hook_fn, remove_hook_fn) = match get_hook_functions(dll_handle) {
            Some(funcs) => funcs,
            None => {
                error!("Failed to resolve hook functions");
                let _ = FreeLibrary(dll_handle);
                return;
            }
        };

        // Create readiness event for hook synchronization
        let ready_event = match create_readiness_event() {
            Ok(event) => event,
            Err(e) => {
                error!(error = %e, "Failed to create readiness event");
                let _ = FreeLibrary(dll_handle);
                return;
            }
        };

        info!("Installing hook...");
        if !install_hook_fn(explorer_thread_id).as_bool() {
            error!("Hook installation failed");
            let _ = CloseHandle(ready_event);
            let _ = FreeLibrary(dll_handle);
            return;
        }

        // Trigger hook by sending a message to the clock window
        if let Some(clock_hwnd) = find_clock_window(taskbar) {
            let _ = SendMessageW(clock_hwnd, WM_NULL, Some(WPARAM(0)), Some(LPARAM(0)));
        } else {
            error!("Clock window not found - hook may not initialize");
        }

        // Wait for hook to signal readiness (2-second timeout for safety)
        match WaitForSingleObject(ready_event, 2000) {
            WAIT_OBJECT_0 => {
                info!("Hook initialized successfully");
            }
            WAIT_TIMEOUT => {
                error!("Hook readiness timeout - continuing anyway");
            }
            result => {
                error!(wait_result = ?result, "Unexpected wait result");
            }
        }

        if let Some(clock_hwnd) = find_clock_window(taskbar) {
            let _ = InvalidateRect(Some(clock_hwnd), None, true);
            let _ = UpdateWindow(clock_hwnd);
        }

        // Start IPC event polling thread
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        let ipc_thread = std::thread::spawn(move || {
            // Create TracingEventReceiver for replaying hook events
            let mut receiver = tracing_tunnel::TracingEventReceiver::default();

            loop {
                if stop_flag_clone.load(Ordering::Acquire) {
                    break;
                }

                // Poll and process events from the hook
                ipc::process_events(&mut ipc_consumer, &mut receiver);

                // Poll at ~60Hz
                std::thread::sleep(std::time::Duration::from_millis(16));
            }
        });

        // Wait for CTRL+C
        let (tx, rx) = std::sync::mpsc::channel();
        ctrlc::set_handler(move || {
            let _ = tx.send(());
        })
        .expect("Error setting CTRL+C handler");

        let _ = rx.recv();

        // Signal the IPC polling thread to stop and wait for it
        stop_flag.store(true, Ordering::Release);
        if let Err(e) = ipc_thread.join() {
            error!(error = ?e, "IPC thread panicked");
        }

        info!("Removing hook");
        let _ = remove_hook_fn();

        let _ = CloseHandle(ready_event);
        let _ = FreeLibrary(dll_handle);
    }

    info!("Cleanup complete");
}

unsafe fn find_taskbar() -> Option<HWND> {
    match FindWindowA(s!("Shell_TrayWnd"), None) {
        Ok(hwnd) if !hwnd.is_invalid() => Some(hwnd),
        _ => None,
    }
}

unsafe fn get_explorer_info(taskbar: HWND) -> Option<(u32, u32)> {
    let mut process_id = 0u32;
    let thread_id = GetWindowThreadProcessId(taskbar, Some(&mut process_id));
    if thread_id == 0 {
        None
    } else {
        Some((thread_id, process_id))
    }
}

unsafe fn load_hook_dll() -> std::result::Result<HMODULE, String> {
    let dll_path = get_dll_path();
    debug!(path = %dll_path.display(), "Loading hook library");

    let dll_path_wide: Vec<u16> = OsStr::new(dll_path.to_str().unwrap())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    LoadLibraryW(PCWSTR(dll_path_wide.as_ptr())).map_err(|e| format!("Library load failed: {}", e))
}

unsafe fn get_hook_functions(dll_handle: HMODULE) -> Option<(InstallHookFn, RemoveHookFn)> {
    let install_fn = GetProcAddress(dll_handle, s!("InstallHook"))?;
    let remove_fn = GetProcAddress(dll_handle, s!("RemoveHook"))?;

    debug!("Resolved hook function pointers");

    Some((
        std::mem::transmute::<unsafe extern "system" fn() -> isize, InstallHookFn>(install_fn),
        std::mem::transmute::<unsafe extern "system" fn() -> isize, RemoveHookFn>(remove_fn),
    ))
}

unsafe fn find_clock_window(taskbar: HWND) -> Option<HWND> {
    let tray = FindWindowExA(Some(taskbar), None, s!("TrayNotifyWnd"), None).ok()?;
    let clock = FindWindowExA(Some(tray), None, s!("TrayClockWClass"), None).ok()?;
    Some(clock)
}

fn get_dll_path() -> PathBuf {
    let mut exe_path = std::env::current_exe().expect("Failed to get executable path");
    exe_path.pop();
    exe_path.push("hook.dll");
    exe_path
}

unsafe fn create_readiness_event() -> std::result::Result<HANDLE, String> {
    let event_name_wide: Vec<u16> = OsStr::new(shared::READY_EVENT_NAME)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    CreateEventW(
        None,  // Default security attributes
        false, // Auto-reset event
        false, // Initially unsignaled
        PCWSTR(event_name_wide.as_ptr()),
    )
    .map_err(|e| format!("Failed to create event: {}", e))
}
