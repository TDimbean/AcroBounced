#![windows_subsystem = "windows"]

use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};
use std::thread;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND, LPARAM, LRESULT, POINT,
    RPC_E_TOO_LATE, WPARAM,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::ProcessStatus::K32EnumProcesses;
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Threading::{
    CreateMutexW, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess,
};
use windows::Win32::System::Variant::{VARIANT, VT_I4, VT_UI4, VT_UNKNOWN, VariantClear};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
    WbemLocator,
};
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW, Shell_NotifyIconW,
    ShellExecuteW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GetCursorPos, GetMessageW, HMENU, KillTimer, LoadIconW, MB_ICONERROR,
    MB_ICONINFORMATION, MB_OK, MF_SEPARATOR, MF_STRING, MSG, MessageBoxW, PostQuitMessage,
    RegisterClassW, SW_SHOWNORMAL, SetForegroundWindow, SetTimer, TPM_RETURNCMD, TrackPopupMenu,
    TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_COMMAND, WM_DESTROY,
    WM_LBUTTONDBLCLK, WM_RBUTTONUP, WM_TIMER, WNDCLASSW,
};
use windows::core::{BSTR, Interface, PCWSTR, PWSTR, w};

const TRAY_MESSAGE: u32 = WM_APP + 1;
const OPEN_CONFIG: usize = 1;
const RELOAD_RULES: usize = 2;
const TOGGLE_PAUSE: usize = 3;
const OPEN_LOG: usize = 4;
const EXIT: usize = 5;
const FALLBACK_TIMER: usize = 1;
const MAX_LOG_BYTES: u64 = 1_048_576;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProcessRule {
    path: String,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    #[serde(default)]
    allow_manual_launch: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    processes: Vec<ProcessRule>,
}

struct AppState {
    config_path: PathBuf,
    log_path: PathBuf,
    rules: RwLock<Vec<ProcessRule>>,
    paused: AtomicBool,
    exiting: AtomicBool,
    events_unavailable: AtomicBool,
}

static STATE: OnceLock<AppState> = OnceLock::new();

fn enabled_by_default() -> bool {
    true
}

fn main() {
    if let Err(error) = run() {
        show_message("AcroBounced", &error, MB_OK | MB_ICONERROR);
    }
}

fn run() -> Result<(), String> {
    let mutex = unsafe { CreateMutexW(None, true, w!("Local\\AcroBounced")) }
        .map_err(|error| error.to_string())?;
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        show_message(
            "AcroBounced",
            "AcroBounced is already running.",
            MB_OK | MB_ICONINFORMATION,
        );
        unsafe { CloseHandle(mutex) }.ok();
        return Ok(());
    }

    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let directory = executable
        .parent()
        .ok_or_else(|| "Cannot determine the executable directory.".to_string())?;
    let config_path = directory.join("AcroBounced.json");
    let log_path = directory.join("AcroBounced.log");
    ensure_config(&config_path)?;
    let rules = load_rules(&config_path)?;

    STATE
        .set(AppState {
            config_path,
            log_path,
            rules: RwLock::new(rules),
            paused: AtomicBool::new(false),
            exiting: AtomicBool::new(false),
            events_unavailable: AtomicBool::new(false),
        })
        .map_err(|_| "Cannot initialize application state.".to_string())?;

    kill_running_matches();
    let watcher = thread::spawn(watch_process_starts);
    let message_result = unsafe { message_loop() };
    STATE.get().unwrap().exiting.store(true, Ordering::Relaxed);
    let _ = watcher.join();
    unsafe { CloseHandle(mutex) }.ok();
    message_result
}

fn ensure_config(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }

    let config = Config {
        processes: vec![
            ProcessRule {
                path: r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe".to_string(),
                enabled: true,
                allow_manual_launch: false,
            },
            ProcessRule {
                path: r"C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe".to_string(),
                enabled: true,
                allow_manual_launch: false,
            },
        ],
    };
    let json = serde_json::to_string_pretty(&config).map_err(|error| error.to_string())?;
    fs::write(path, format!("{json}\n"))
        .map_err(|error| format!("Cannot create {}: {error}", path.display()))
}

fn load_rules(path: &Path) -> Result<Vec<ProcessRule>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
    let mut config: Config = serde_json::from_str(&contents)
        .map_err(|error| format!("Invalid {}: {error}", path.display()))?;
    for rule in &mut config.processes {
        rule.path = normalize_path(&rule.path);
    }
    Ok(config.processes)
}

fn normalize_path(path: &str) -> String {
    let expanded = expand_environment(path).unwrap_or_else(|| path.to_string());
    let canonical = fs::canonicalize(&expanded).unwrap_or_else(|_| PathBuf::from(&expanded));
    canonical
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .replace('/', "\\")
        .to_lowercase()
}

fn expand_environment(value: &str) -> Option<String> {
    let source = wide(value);
    let needed = unsafe { ExpandEnvironmentStringsW(PCWSTR(source.as_ptr()), None) };
    if needed == 0 {
        return None;
    }
    let mut output = vec![0u16; needed as usize];
    let written = unsafe { ExpandEnvironmentStringsW(PCWSTR(source.as_ptr()), Some(&mut output)) };
    (written != 0).then(|| String::from_utf16_lossy(&output[..written.saturating_sub(1) as usize]))
}

fn kill_running_matches() {
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(snapshot) => snapshot,
        Err(error) => {
            log_event(
                "ERROR",
                &format!("Cannot enumerate running processes: {error}"),
            );
            return;
        }
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            inspect_and_kill(
                entry.th32ProcessID,
                entry.th32ParentProcessID,
                "already running",
            );
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot) }.ok();
}

fn inspect_and_kill(pid: u32, parent_pid: u32, reason: &str) {
    if STATE.get().unwrap().paused.load(Ordering::Relaxed) {
        return;
    }
    let process = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            false,
            pid,
        )
    } {
        Ok(process) => process,
        Err(_) => return,
    };
    let path = process_path(process);
    let is_blocked = path.as_ref().is_some_and(|path| {
        STATE
            .get()
            .unwrap()
            .rules
            .read()
            .unwrap()
            .iter()
            .any(|rule| rule.enabled && rule.path == *path)
    });

    if is_blocked {
        let path = path.unwrap();
        match unsafe { TerminateProcess(process, 1) } {
            Ok(()) => log_event(
                "BLOCKED_PROCESS",
                &format!("PID={pid} ParentPID={parent_pid} Path={path} Reason={reason}"),
            ),
            Err(error) => log_event(
                "ERROR",
                &format!("Cannot terminate PID={pid} Path={path}: {error}"),
            ),
        }
    }
    unsafe { CloseHandle(process) }.ok();
}

fn process_path(process: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            process,
            Default::default(),
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .ok()
    .map(|_| normalize_path(&String::from_utf16_lossy(&buffer[..length as usize])))
}

fn watch_process_starts() {
    if let Err(error) = unsafe { watch_process_starts_inner() } {
        log_event(
            "ERROR",
            &format!("Process events unavailable ({error}); using 1-second fallback scan"),
        );
        STATE
            .get()
            .unwrap()
            .events_unavailable
            .store(true, Ordering::Relaxed);
    }
}

fn scan_running_matches() {
    let Some(processes) = process_ids() else {
        log_event("ERROR", "Fallback process snapshot failed");
        return;
    };
    for pid in processes {
        inspect_and_kill(pid, 0, "new launch");
    }
}

fn process_ids() -> Option<Vec<u32>> {
    let mut ids = vec![0u32; 16_384];
    let mut bytes = 0;
    if !unsafe {
        K32EnumProcesses(
            ids.as_mut_ptr(),
            (ids.len() * size_of::<u32>()) as u32,
            &mut bytes,
        )
    }
    .as_bool()
    {
        return None;
    }
    ids.truncate(bytes as usize / size_of::<u32>());
    ids.retain(|pid| *pid != 0);
    Some(ids)
}

unsafe fn watch_process_starts_inner() -> windows::core::Result<()> {
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok()?;
    let security = unsafe {
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
    };
    if let Err(error) = security
        && error.code() != RPC_E_TOO_LATE
    {
        unsafe { CoUninitialize() };
        return Err(error);
    }

    let locator: IWbemLocator =
        unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }?;
    let empty = BSTR::new();
    let services = unsafe {
        locator.ConnectServer(
            &BSTR::from("ROOT\\CIMV2"),
            &empty,
            &empty,
            &empty,
            0,
            &empty,
            None,
        )
    }?;
    unsafe {
        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    }?;
    let trace_events = unsafe {
        services.ExecNotificationQuery(
            &BSTR::from("WQL"),
            &BSTR::from("SELECT ProcessID, ParentProcessID FROM Win32_ProcessStartTrace"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    };
    let (events, uses_trace_events) = match trace_events {
        Ok(events) => (events, true),
        Err(_) => (
            unsafe {
                services.ExecNotificationQuery(
                    &BSTR::from("WQL"),
                    &BSTR::from(
                        "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'",
                    ),
                    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                    None,
                )
            }?,
            false,
        ),
    };

    while !STATE.get().unwrap().exiting.load(Ordering::Relaxed) {
        let mut objects: [Option<IWbemClassObject>; 1] = [None];
        let mut returned = 0;
        let result = unsafe { events.Next(1_000, &mut objects, &mut returned) };
        if result.is_err() {
            unsafe { CoUninitialize() };
            return Err(result.into());
        }
        if returned == 1
            && let Some(event) = objects[0].take()
        {
            let process = if uses_trace_events {
                Some(event)
            } else {
                unsafe { object_property(&event, w!("TargetInstance")) }
            };
            let Some(process) = process else {
                continue;
            };
            let pid_name = if uses_trace_events {
                w!("ProcessID")
            } else {
                w!("ProcessId")
            };
            let parent_name = if uses_trace_events {
                w!("ParentProcessID")
            } else {
                w!("ParentProcessId")
            };
            let Some(pid) = (unsafe { uint_property(&process, pid_name) }) else {
                continue;
            };
            let parent_pid = unsafe { uint_property(&process, parent_name) }.unwrap_or(0);
            inspect_and_kill(pid, parent_pid, "new launch");
        }
    }
    unsafe { CoUninitialize() };
    Ok(())
}

unsafe fn uint_property(object: &IWbemClassObject, name: PCWSTR) -> Option<u32> {
    let mut value = VARIANT::default();
    if unsafe { object.Get(name, 0, &mut value, None, None) }.is_err() {
        return None;
    }
    let inner = unsafe { &value.Anonymous.Anonymous };
    let result = if inner.vt == VT_UI4 {
        Some(unsafe { inner.Anonymous.ulVal })
    } else if inner.vt == VT_I4 {
        Some(unsafe { inner.Anonymous.lVal as u32 })
    } else {
        None
    };
    unsafe { VariantClear(&mut value) }.ok();
    result
}

unsafe fn object_property(object: &IWbemClassObject, name: PCWSTR) -> Option<IWbemClassObject> {
    let mut value = VARIANT::default();
    if unsafe { object.Get(name, 0, &mut value, None, None) }.is_err() {
        return None;
    }
    let inner = unsafe { &value.Anonymous.Anonymous };
    let result = if inner.vt == VT_UNKNOWN {
        let unknown =
            std::mem::ManuallyDrop::into_inner(unsafe { inner.Anonymous.punkVal.clone() });
        unknown.and_then(|unknown| unknown.cast().ok())
    } else {
        None
    };
    unsafe { VariantClear(&mut value) }.ok();
    result
}

fn log_event(event: &str, details: &str) {
    let state = STATE.get().unwrap();
    if fs::metadata(&state.log_path).is_ok_and(|metadata| metadata.len() >= MAX_LOG_BYTES) {
        let old_path = state.log_path.with_extension("log.old");
        let _ = fs::remove_file(&old_path);
        let _ = fs::rename(&state.log_path, old_path);
    }
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&state.log_path)
    {
        let _ = writeln!(
            file,
            "{} {event} {details}",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        );
    }
}

unsafe fn message_loop() -> Result<(), String> {
    let instance = unsafe { GetModuleHandleW(None) }.map_err(|error| error.to_string())?;
    let class = w!("AcroBouncedTrayWindow");
    let window_class = WNDCLASSW {
        hInstance: instance.into(),
        lpszClassName: class,
        lpfnWndProc: Some(window_proc),
        ..Default::default()
    };
    if unsafe { RegisterClassW(&window_class) } == 0 {
        return Err("Cannot register the tray window.".to_string());
    }
    let window = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            w!("AcroBounced"),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance.into()),
            None,
        )
    }
    .map_err(|error| error.to_string())?;

    let tray = tray_data(window)?;
    if !unsafe { Shell_NotifyIconW(NIM_ADD, &tray) }.as_bool() {
        return Err("Cannot create the tray icon.".to_string());
    }
    if unsafe { SetTimer(Some(window), FALLBACK_TIMER, 1_000, None) } == 0 {
        return Err("Cannot create the fallback monitor timer.".to_string());
    }

    let mut message = MSG::default();
    while unsafe { GetMessageW(&mut message, None, 0, 0) }.as_bool() {
        let _ = unsafe { TranslateMessage(&message) };
        unsafe { DispatchMessageW(&message) };
    }
    Ok(())
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        TRAY_MESSAGE if lparam.0 as u32 == WM_RBUTTONUP => unsafe { show_tray_menu(window) },
        TRAY_MESSAGE if lparam.0 as u32 == WM_LBUTTONDBLCLK => {
            open_file(&STATE.get().unwrap().config_path)
        }
        WM_COMMAND => handle_command(window, wparam.0 & 0xffff),
        WM_TIMER
            if wparam.0 == FALLBACK_TIMER
                && STATE
                    .get()
                    .unwrap()
                    .events_unavailable
                    .load(Ordering::Relaxed) =>
        {
            scan_running_matches();
        }
        WM_DESTROY => {
            STATE.get().unwrap().exiting.store(true, Ordering::Relaxed);
            unsafe { KillTimer(Some(window), FALLBACK_TIMER) }.ok();
            if let Ok(tray) = tray_data(window) {
                let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &tray) };
            }
            unsafe { PostQuitMessage(0) };
        }
        _ => return unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
    LRESULT(0)
}

fn handle_command(window: HWND, command: usize) {
    let state = STATE.get().unwrap();
    match command {
        OPEN_CONFIG => open_file(&state.config_path),
        RELOAD_RULES => match load_rules(&state.config_path) {
            Ok(rules) => {
                *state.rules.write().unwrap() = rules;
                kill_running_matches();
                show_message("AcroBounced", "Rules reloaded.", MB_OK | MB_ICONINFORMATION);
            }
            Err(error) => show_message("AcroBounced", &error, MB_OK | MB_ICONERROR),
        },
        TOGGLE_PAUSE => {
            let paused = !state.paused.load(Ordering::Relaxed);
            state.paused.store(paused, Ordering::Relaxed);
            log_event(if paused { "PAUSED" } else { "RESUMED" }, "Tray command");
        }
        OPEN_LOG => {
            if !state.log_path.exists() {
                let _ = File::create(&state.log_path);
            }
            open_file(&state.log_path);
        }
        EXIT => unsafe {
            DestroyWindow(window).ok();
        },
        _ => {}
    }
}

unsafe fn show_tray_menu(window: HWND) {
    let menu = match unsafe { CreatePopupMenu() } {
        Ok(menu) => menu,
        Err(_) => return,
    };
    let paused = STATE.get().unwrap().paused.load(Ordering::Relaxed);
    add_menu_item(menu, OPEN_CONFIG, "Open blacklist");
    add_menu_item(menu, RELOAD_RULES, "Reload rules and sweep now");
    add_menu_item(
        menu,
        TOGGLE_PAUSE,
        if paused {
            "Resume blocking"
        } else {
            "Pause blocking"
        },
    );
    unsafe { AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null()) }.ok();
    add_menu_item(menu, OPEN_LOG, "Open log");
    add_menu_item(menu, EXIT, "Exit");

    let mut point = POINT::default();
    if unsafe { GetCursorPos(&mut point) }.is_ok() {
        let _ = unsafe { SetForegroundWindow(window) };
        let command =
            unsafe { TrackPopupMenu(menu, TPM_RETURNCMD, point.x, point.y, None, window, None) }.0;
        if command != 0 {
            handle_command(window, command as usize);
        }
    }
    unsafe { DestroyMenu(menu) }.ok();
}

fn add_menu_item(menu: HMENU, id: usize, label: &str) {
    let label = wide(label);
    unsafe { AppendMenuW(menu, MF_STRING, id, PCWSTR(label.as_ptr())) }.ok();
}

fn tray_data(window: HWND) -> Result<NOTIFYICONDATAW, String> {
    let instance = unsafe { GetModuleHandleW(None) }.map_err(|error| error.to_string())?;
    let resource = PCWSTR(std::ptr::without_provenance(1));
    let icon =
        unsafe { LoadIconW(Some(instance.into()), resource) }.map_err(|error| error.to_string())?;
    let mut data = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: TRAY_MESSAGE,
        hIcon: icon,
        ..Default::default()
    };
    copy_wide(&mut data.szTip, "AcroBounced — blocking enabled");
    Ok(data)
}

fn open_file(path: &Path) {
    let path = wide(&path.to_string_lossy());
    unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

fn show_message(
    title: &str,
    text: &str,
    style: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE,
) {
    let title = wide(title);
    let text = wide(text);
    unsafe {
        MessageBoxW(None, PCWSTR(text.as_ptr()), PCWSTR(title.as_ptr()), style);
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn copy_wide<const N: usize>(target: &mut [u16; N], value: &str) {
    let value = value.encode_utf16().take(N - 1);
    for (slot, character) in target.iter_mut().zip(value) {
        *slot = character;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_windows_paths_case_insensitively() {
        assert_eq!(
            normalize_path(r"C:/Program Files/Adobe/Acrobat.exe"),
            r"c:\program files\adobe\acrobat.exe"
        );
    }

    #[test]
    fn accepts_spec_config_shape() {
        let config: Config = serde_json::from_str(
            r#"{"processes":[{"path":"C:\\Apps\\Blocked.exe","enabled":true,"allow_manual_launch":true}]}"#,
        )
        .unwrap();
        assert_eq!(config.processes.len(), 1);
        assert!(config.processes[0].allow_manual_launch);
    }

    #[test]
    fn enumerates_current_process() {
        assert!(process_ids().unwrap().contains(&std::process::id()));
    }
}
