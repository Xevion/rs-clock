//! Launcher that injects the hook DLL into Explorer.exe to customize the Windows clock.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use tracing::{debug, error, info, Level};
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::UI::WindowsAndMessaging::*;

type InstallHookFn = unsafe extern "system" fn(HINSTANCE, u32) -> BOOL;
type RemoveHookFn = unsafe extern "system" fn() -> BOOL;

fn main() {
    tracing_subscriber::fmt()
        .compact()
        .with_max_level(Level::DEBUG)
        .init();

    info!("RS-Clock - Windows Clock Hook");

    unsafe {
        let taskbar = match find_taskbar() {
            Some(hwnd) => {
                info!(hwnd = ?hwnd, "Located taskbar window");
                hwnd
            }
            None => {
                error!("Failed to locate taskbar window");
                return;
            }
        };

        let (explorer_thread_id, _explorer_process_id) = match get_explorer_info(taskbar) {
            Some(info) => {
                debug!(thread_id = info.0, process_id = info.1, "Retrieved Explorer identifiers");
                info
            }
            None => {
                error!("Failed to retrieve Explorer thread information");
                return;
            }
        };

        let dll_handle = match load_hook_dll() {
            Ok(handle) => {
                debug!(handle = ?handle, "Hook library loaded");
                handle
            }
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

        info!("Installing hook into Explorer process");
        if !install_hook_fn(dll_handle.into(), explorer_thread_id).as_bool() {
            error!("Hook installation failed");
            let _ = FreeLibrary(dll_handle);
            return;
        }
        info!("Hook installation successful");

        std::thread::sleep(std::time::Duration::from_millis(200));

        if let Some(clock_hwnd) = find_clock_window(taskbar) {
            debug!(hwnd = ?clock_hwnd, "Triggering initial clock repaint");
            let _ = InvalidateRect(Some(clock_hwnd), None, true);
            let _ = UpdateWindow(clock_hwnd);
        }

        info!("Hook active");
        println!("\nPress Enter to exit and restore default clock...");

        let mut input = String::new();
        let _ = io::stdin().read_line(&mut input);

        info!("Removing hook");
        let _ = remove_hook_fn();
        debug!("Hook removed");

        let _ = FreeLibrary(dll_handle);
    }

    info!("Shutdown complete");
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
    info!(path = %dll_path.display(), "Loading hook library");

    let dll_path_wide: Vec<u16> = OsStr::new(dll_path.to_str().unwrap())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    LoadLibraryW(PCWSTR(dll_path_wide.as_ptr()))
        .map_err(|e| format!("Library load failed: {}", e))
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
