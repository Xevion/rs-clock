//! Hook DLL that intercepts Windows clock messages and renders custom content.

use std::sync::atomic::{AtomicIsize, Ordering};
use tracing::{debug, info};
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;

static CLOCK_HWND: AtomicIsize = AtomicIsize::new(0);
static HOOK_HANDLE: AtomicIsize = AtomicIsize::new(0);

const SUBCLASS_ID: usize = 1;
const WINDOWS_TIMER_ID: usize = 0;

/// # Safety
/// Called by Windows DLL loader with valid parameters.
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _dll_instance: HINSTANCE,
    reason: u32,
    _reserved: *const std::ffi::c_void,
) -> BOOL {
    match reason {
        1 => TRUE, // DLL_PROCESS_ATTACH
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
    if code >= 0 {
        let window_msg = *(lparam.0 as *const CWPSTRUCT);

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
/// Caller must ensure dll_instance is valid and thread_id exists.
#[no_mangle]
pub unsafe extern "system" fn InstallHook(dll_instance: HINSTANCE, thread_id: u32) -> BOOL {
    let hook = SetWindowsHookExW(
        WH_CALLWNDPROC,
        Some(HookProc),
        Some(dll_instance),
        thread_id,
    );

    match hook {
        Ok(h) => {
            HOOK_HANDLE.store(h.0 as isize, Ordering::Relaxed);
            info!(thread_id, "Hook installed");
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
            info!("Hook removed");
            TRUE
        } else {
            FALSE
        }
    } else {
        FALSE
    }
}

unsafe fn is_clock_window(hwnd: HWND) -> bool {
    let mut class_name = [0u16; 256];
    if GetClassNameW(hwnd, &mut class_name) > 0 {
        let name = String::from_utf16_lossy(&class_name);
        let is_clock = name.starts_with("TrayClockWClass");
        if is_clock {
            debug!(hwnd = ?hwnd, class = %name, "Clock window detected");
        }
        is_clock
    } else {
        false
    }
}

unsafe fn install_clock_subclass(hwnd: HWND) {
    if SetWindowSubclass(hwnd, Some(clock_subclass_proc), SUBCLASS_ID, 0).as_bool() {
        CLOCK_HWND.store(hwnd.0 as isize, Ordering::Relaxed);

        let _ = KillTimer(Some(hwnd), WINDOWS_TIMER_ID);
        let _ = InvalidateRect(Some(hwnd), None, true);

        info!(hwnd = ?hwnd, "Subclass installed");
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

unsafe fn cleanup() {
    let _ = RemoveHook();

    let hwnd_val = CLOCK_HWND.load(Ordering::Relaxed);
    if hwnd_val != 0 {
        let hwnd = HWND(hwnd_val as *mut _);
        let _ = RemoveWindowSubclass(hwnd, Some(clock_subclass_proc), SUBCLASS_ID);
        let _ = InvalidateRect(Some(hwnd), None, true);
    }
}
