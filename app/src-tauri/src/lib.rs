//! ThreatSketch desktop: the web app in a native window. The only native code hands the app the
//! files the operating system asked it to open (double-clicked `.tm7` files, or paths on the
//! command line on Windows and Linux).

use std::sync::Mutex;
use tauri::{Emitter, Manager};

#[derive(serde::Serialize, Clone)]
struct OpenedFile {
    name: String,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Pending(Mutex<Vec<std::path::PathBuf>>);

fn read(paths: Vec<std::path::PathBuf>) -> Vec<OpenedFile> {
    paths
        .into_iter()
        .filter_map(|p| {
            let bytes = std::fs::read(&p).ok()?;
            let name = p.file_name()?.to_string_lossy().into_owned();
            Some(OpenedFile { name, bytes })
        })
        .collect()
}

/// Files the OS asked us to open before the page was ready to receive them.
#[tauri::command]
fn take_opened_files(pending: tauri::State<Pending>) -> Vec<OpenedFile> {
    read(std::mem::take(&mut *pending.0.lock().unwrap()))
}

/// Smoke test for desktop builds: with THREATSKETCH_SELFTEST=<file> set, the app opens the
/// example, writes what happened to <file> and quits. With THREATSKETCH_SELFTEST_UPDATE=1 as
/// well, it first installs any available update and restarts into it.
#[tauri::command]
fn selftest_mode() -> &'static str {
    match (std::env::var_os("THREATSKETCH_SELFTEST"), std::env::var_os("THREATSKETCH_SELFTEST_UPDATE")) {
        (None, _) => "",
        (Some(_), None) => "run",
        (Some(_), Some(_)) => "update",
    }
}

#[tauri::command]
fn selftest_report(app: tauri::AppHandle, report: String) {
    if let Some(path) = std::env::var_os("THREATSKETCH_SELFTEST") {
        let _ = std::fs::write(path, report);
    }
    app.exit(0);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .manage(Pending::default())
        .setup(|app| {
            #[cfg(desktop)]
            app.handle().plugin(tauri_plugin_updater::Builder::new().build())?;
            let args: Vec<_> = std::env::args_os().skip(1).map(std::path::PathBuf::from).filter(|p| p.is_file()).collect();
            app.state::<Pending>().0.lock().unwrap().extend(args);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![take_opened_files, selftest_mode, selftest_report])
        .build(tauri::generate_context!())
        .expect("error while starting ThreatSketch")
        .run(|_app, _event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Opened { urls } = _event {
                let paths: Vec<_> = urls.iter().filter_map(|u| u.to_file_path().ok()).collect();
                _app.state::<Pending>().0.lock().unwrap().extend(paths);
                let _ = _app.emit("files-opened", ());
            }
        });
}
