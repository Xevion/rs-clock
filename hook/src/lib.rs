//! Hook DLL that intercepts Windows clock messages and renders custom content.

mod ipc;
mod tracing_layer;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicIsize, Ordering};
use tracing::debug;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Threading::*;
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;

static CLOCK_HWND: AtomicIsize = AtomicIsize::new(0);
static HOOK_HANDLE: AtomicIsize = AtomicIsize::new(0);
static DLL_INSTANCE: AtomicIsize = AtomicIsize::new(0);
static TRACING_INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

const SUBCLASS_ID: usize = 1;
const WINDOWS_TIMER_ID: usize = 0;

/// Get the current process executable name (e.g., "explorer.exe" or "launcher.exe")
unsafe fn get_current_process_name() -> String {
    let mut buffer = [0u16; 260]; // MAX_PATH
    let len = GetModuleFileNameW(None, &mut buffer);

    if len > 0 && (len as usize) < buffer.len() {
        let path = String::from_utf16_lossy(&buffer[..len as usize]);
        // Extract just the filename from the full path
        path.rsplit('\\')
            .next()
            .unwrap_or(&path)
            .to_lowercase()
    } else {
        String::new()
    }
}

/// # Safety
/// Called by Windows DLL loader with valid parameters.
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    dll_instance: HINSTANCE,
    reason: u32,
    _reserved: *const std::ffi::c_void,
) -> BOOL {
    match reason {
        1 => {
            // DLL_PROCESS_ATTACH
            // Store the DLL instance for later use
            DLL_INSTANCE.store(dll_instance.0 as isize, Ordering::Relaxed);

            // Only initialize tracing when loaded into Explorer, not the launcher
            let process_name = get_current_process_name();
            let is_explorer = process_name.contains("explorer");

            if is_explorer && TRACING_INITIALIZED
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                match tracing_layer::create_ipc_subscriber() {
                    Ok(subscriber) => {
                        if tracing::subscriber::set_global_default(subscriber).is_ok() {
                            debug!("Hook DLL loaded into Explorer process");
                        }
                    }
                    Err(e) => {
                        // IPC not available - log to stderr as fallback
                        eprintln!("hook: Failed to initialize IPC tracing: {}", e);
                        eprintln!("hook: Trace events will not be visible");
                    }
                }
            }
            TRUE
        }
        0 => {
            cleanup();
            TRUE
        }
        _ => TRUE,
    }
}

/// # Safety
/// Dereferences raw pointer from lparam as CWPSTRUCT.
#[no_mangle]
pub unsafe extern "system" fn HookProc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && lparam.0 != 0 {
        let window_msg = &*(lparam.0 as *const CWPSTRUCT);

        if is_clock_window(window_msg.hwnd) && CLOCK_HWND.load(Ordering::Relaxed) == 0 {
            install_clock_subclass(window_msg.hwnd);
        }
    }

    CallNextHookEx(None, code, wparam, lparam)
}

unsafe extern "system" fn clock_subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _subclass_id: usize,
    _ref_data: usize,
) -> LRESULT {
    match msg {
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);

            if !hdc.is_invalid() {
                let mut rect = RECT::default();
                let _ = GetClientRect(hwnd, &mut rect);
                render_clock_display(hdc, &rect);
                let _ = EndPaint(hwnd, &ps);
            }

            LRESULT(0)
        }
        WM_ERASEBKGND => LRESULT(1),
        WM_TIMER => {
            if wparam.0 == WINDOWS_TIMER_ID {
                LRESULT(0)
            } else {
                DefSubclassProc(hwnd, msg, wparam, lparam)
            }
        }
        WM_DESTROY => {
            let _ = RemoveWindowSubclass(hwnd, Some(clock_subclass_proc), SUBCLASS_ID);
            DefSubclassProc(hwnd, msg, wparam, lparam)
        }
        _ => DefSubclassProc(hwnd, msg, wparam, lparam),
    }
}

/// # Safety
/// Caller must ensure thread_id exists. This function uses the DLL instance stored during DllMain.
#[no_mangle]
pub unsafe extern "system" fn InstallHook(thread_id: u32) -> BOOL {
    // Get our DLL handle that was stored during DLL_PROCESS_ATTACH
    let dll_instance_raw = DLL_INSTANCE.load(Ordering::Relaxed);
    if dll_instance_raw == 0 {
        return FALSE;
    }
    let dll_instance = HINSTANCE(dll_instance_raw as *mut _);

    let hook = SetWindowsHookExW(
        WH_CALLWNDPROC,
        Some(HookProc),
        Some(dll_instance),
        thread_id,
    );

    match hook {
        Ok(h) => {
            HOOK_HANDLE.store(h.0 as isize, Ordering::Relaxed);
            debug!(
                thread_id = format_args!("0x{:08x}", thread_id),
                "Hook installed in thread"
            );
            TRUE
        }
        Err(_) => FALSE,
    }
}

/// # Safety
/// Safe to call multiple times; handles null hook internally.
#[no_mangle]
pub unsafe extern "system" fn RemoveHook() -> BOOL {
    let hook_val = HOOK_HANDLE.load(Ordering::Relaxed);
    if hook_val != 0 {
        let hook = HHOOK(hook_val as *mut _);
        let result = UnhookWindowsHookEx(hook);
        HOOK_HANDLE.store(0, Ordering::Relaxed);
        if result.is_ok() {
            debug!("Hook uninstalled");
            TRUE
        } else {
            FALSE
        }
    } else {
        FALSE
    }
}

unsafe fn is_clock_window(hwnd: HWND) -> bool {
    const CLOCK_CLASS_PREFIX: &[u16] = &[
        'T' as u16, 'r' as u16, 'a' as u16, 'y' as u16, 'C' as u16, 'l' as u16, 'o' as u16,
        'c' as u16, 'k' as u16, 'W' as u16, 'C' as u16, 'l' as u16, 'a' as u16, 's' as u16,
        's' as u16,
    ]; // "TrayClockWClass"

    let mut class_name = [0u16; 256];
    let len = GetClassNameW(hwnd, &mut class_name);
    if len as usize >= CLOCK_CLASS_PREFIX.len() {
        // Compare UTF-16 directly without allocating a String
        class_name[..CLOCK_CLASS_PREFIX.len()] == *CLOCK_CLASS_PREFIX
    } else {
        false
    }
}

unsafe fn install_clock_subclass(hwnd: HWND) {
    if SetWindowSubclass(hwnd, Some(clock_subclass_proc), SUBCLASS_ID, 0).as_bool() {
        CLOCK_HWND.store(hwnd.0 as isize, Ordering::Relaxed);

        let _ = KillTimer(Some(hwnd), WINDOWS_TIMER_ID);
        let _ = InvalidateRect(Some(hwnd), None, true);

        debug!("Clock window subclassed");

        // Signal readiness to launcher
        signal_hook_ready();
    }
}

unsafe fn render_clock_display(hdc: HDC, rect: &RECT) {
    let bg_brush = CreateSolidBrush(COLORREF(0x00202020));
    let _ = FillRect(hdc, rect, bg_brush);
    let _ = DeleteObject(bg_brush.into());

    let _ = SetBkMode(hdc, TRANSPARENT);
    let _ = SetTextColor(hdc, COLORREF(0x0000FF00));

    let text = "RUST CLOCK!";
    let mut text_wide: Vec<u16> = text.encode_utf16().collect();

    let _ = DrawTextW(
        hdc,
        &mut text_wide,
        &mut rect.clone(),
        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
    );
}

unsafe fn signal_hook_ready() {
    let event_name_wide: Vec<u16> = OsStr::new(shared::READY_EVENT_NAME)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    match OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(event_name_wide.as_ptr())) {
        Ok(event) => {
            let _ = SetEvent(event);
            let _ = CloseHandle(event);
            debug!("Signaled readiness to launcher");
        }
        Err(e) => {
            debug!(error = ?e, "Failed to signal readiness (launcher may not be waiting)");
        }
    }
}

unsafe fn cleanup() {
    let _ = RemoveHook();

    let hwnd_val = CLOCK_HWND.load(Ordering::Relaxed);
    if hwnd_val != 0 {
        let hwnd = HWND(hwnd_val as *mut _);
        let _ = RemoveWindowSubclass(hwnd, Some(clock_subclass_proc), SUBCLASS_ID);
        let _ = InvalidateRect(Some(hwnd), None, true);
    }
}
