//! NexLink for Windows — a tray-only app.
//!
//! The app lives in the notification area ("Show hidden icons"). Its one
//! small window holds the transport settings and the Connect button.
//! Connecting is always manual — there is no auto-retry anywhere, by design.
//!
//! Status of this shell: the phone check is real (ADB forwarding + the NXLP
//! handshake, straight from nxcore). The Wintun adapter backend that turns
//! a successful check into a full tunnel is the next milestone; until then
//! the window says so plainly instead of pretending to be connected.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// Wintun adapter backend (Windows only): creates the "NexLink" adapter
/// and pumps packets to/from the engine's channels. Not wired to the UI
/// yet — backlog item 2 does that (hence dead_code for now).
#[cfg(windows)]
#[allow(dead_code)]
mod wintun_backend;

use std::io::Read;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, WindowEvent};

use nxcore::engine::client_handshake;
use nxcore::proto::DEFAULT_PORT;

/// Find adb: next to our exe first (the shipped bundle), then on PATH.
fn adb_command() -> Command {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("adb.exe");
        if sibling.exists() {
            return Command::new(sibling);
        }
    }
    Command::new("adb")
}

fn run_adb_forward() -> Result<(), String> {
    let output = adb_command()
        .args(["forward", &format!("tcp:{DEFAULT_PORT}"), &format!("tcp:{DEFAULT_PORT}")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Could not run adb ({e}). Is USB debugging on and the phone plugged in?"))?;
    if output.status.success() {
        Ok(())
    } else {
        let mut msg = String::new();
        let _ = output.stderr.as_slice().read_to_string(&mut msg);
        Err(format!("adb forward failed: {}", msg.trim()))
    }
}

/// The Connect button: reach the phone and do the NXLP handshake.
/// Returns a human-readable status for the window.
#[tauri::command]
async fn check_phone(transport: String, address: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || check_phone_blocking(&transport, &address))
        .await
        .map_err(|e| format!("internal error: {e}"))?
}

fn check_phone_blocking(transport: &str, address: &str) -> Result<String, String> {
    let target: String = match transport {
        "usb" => {
            run_adb_forward()?;
            format!("127.0.0.1:{DEFAULT_PORT}")
        }
        "wifi" => {
            let ip = address.trim();
            if ip.is_empty() {
                return Err("Enter the phone's Wi-Fi IP address first.".to_string());
            }
            format!("{ip}:{DEFAULT_PORT}")
        }
        "bluetooth" => {
            return Err("The Bluetooth dialer lands in the next milestone — USB and Wi-Fi first.".to_string());
        }
        other => return Err(format!("unknown transport: {other}")),
    };

    let mut stream = TcpStream::connect_timeout(
        &target.parse().map_err(|_| format!("bad address: {target}"))?,
        Duration::from_secs(4),
    )
    .map_err(|e| {
        format!(
            "Could not reach the phone at {target} ({e}). Is 'Allow connection' on in the NexLink app on your phone?"
        )
    })?;

    let hello = client_handshake(&mut stream, "NexLink for Windows")
        .map_err(|e| format!("The phone answered but the handshake failed: {e}"))?;

    if hello.armed {
        Ok(format!(
            "Phone found: {} — armed and ready. (The Wintun adapter that completes the tunnel is the next milestone.)",
            hello.phone_name
        ))
    } else {
        Err("The phone answered but 'Allow connection' is off. Turn it on in the NexLink app on your phone, then press Connect again.".to_string())
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![check_phone])
        .setup(|app| {
            // Closing the settings window hides it; the app lives in the tray.
            if let Some(window) = app.get_webview_window("settings") {
                let w = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = w.hide();
                    }
                });
            }

            let settings_item = MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Exit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&settings_item, &quit_item])?;

            TrayIconBuilder::with_id("nexlink-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("NexLink")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "settings" => {
                        if let Some(window) = app.get_webview_window("settings") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(window) = tray.app_handle().get_webview_window("settings") {
                            if window.is_visible().unwrap_or(false) {
                                let _ = window.hide();
                            } else {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running NexLink");
}
