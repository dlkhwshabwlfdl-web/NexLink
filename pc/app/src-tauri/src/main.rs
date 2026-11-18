//! NexLink for Windows — a tray-only app.
//!
//! The app lives in the notification area ("Show hidden icons"). Its one
//! small window holds the transport settings and the Connect button.
//! Connecting is always manual — there is no auto-retry anywhere, by design.
//!
//! Connect does the real thing now (backlog item 2): after the phone
//! check (armed), it opens the Wintun adapter, installs the tunnel
//! routes, and runs the nxcore engine on its own thread, so all PC
//! traffic flows through the phone. Disconnect — or quitting the app —
//! stops the engine, removes the routes and stops the adapter.
//!
//! The app must run elevated (administrator): creating the adapter and
//! changing routes need it. Until the installer (backlog item 3) adds a
//! UAC manifest, run it with right-click → Run as administrator.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// Wintun adapter backend (Windows only): creates the "NexLink" adapter
/// and pumps packets to/from the engine's channels.
#[cfg(windows)]
mod wintun_backend;

/// Windows route + DNS management for the tunnel (item 2).
#[cfg(windows)]
mod routes;

/// Pure network helpers, unit-tested on every platform. Only used by
/// the Windows routes module — hence the allow on other platforms.
#[allow(dead_code)]
mod netutil;

use std::io::Read;
use std::net::{Ipv4Addr, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, RunEvent, WindowEvent};

use nxcore::engine::client_handshake;
use nxcore::proto::DEFAULT_PORT;

/// One live tunnel: the engine thread plus the flag that stops it.
/// The thread owns the engine, the Wintun device and the routes, and
/// tears them all down when the engine exits — whether it was asked to
/// stop or the link died on its own.
struct ActiveTunnel {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
    summary: String,
}

/// Shared tunnel state, managed by Tauri. Cheap to clone (Arcs inside),
/// so commands can move it into `spawn_blocking`.
#[derive(Clone)]
struct TunnelState {
    inner: Arc<Mutex<Option<ActiveTunnel>>>,
    /// The last tunnel error (engine died / link lost). Cleared on a
    /// successful connect; survives disconnect so the UI can show it.
    last_error: Arc<Mutex<Option<String>>>,
}

impl TunnelState {
    fn new() -> Self {
        TunnelState { inner: Arc::new(Mutex::new(None)), last_error: Arc::new(Mutex::new(None)) }
    }

    /// Stop the engine thread (if any) and clear the state. Always
    /// succeeds; used by the Disconnect command and on app exit.
    fn stop_tunnel(&self) -> String {
        let tunnel = self.inner.lock().unwrap().take();
        let Some(tunnel) = tunnel else {
            return "Not connected.".to_string();
        };
        tunnel.stop.store(true, Ordering::Relaxed);
        let _ = tunnel.thread.join();
        match self.last_error.lock().unwrap().take() {
            Some(e) => format!("Disconnected. Note: the tunnel had already died: {e}"),
            None => "Disconnected — routes removed, adapter stopped.".to_string(),
        }
    }
}

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

/// Reach the phone and do the NXLP handshake. Returns the handshaken
/// link stream (kept open — the engine takes it over), the phone's
/// hello, and the phone's IP on Wi-Fi (needed for the /32 host route).
fn reach_phone(
    transport: &str,
    address: &str,
) -> Result<(TcpStream, nxcore::engine::HelloAckInfo, Option<Ipv4Addr>), String> {
    let (target, phone_ip): (String, Option<Ipv4Addr>) = match transport {
        "usb" => {
            run_adb_forward()?;
            (format!("127.0.0.1:{DEFAULT_PORT}"), None)
        }
        "wifi" => {
            let ip = address.trim();
            if ip.is_empty() {
                return Err("Enter the phone's Wi-Fi IP address first.".to_string());
            }
            let parsed: Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("'{ip}' is not a valid IPv4 address."))?;
            (format!("{ip}:{DEFAULT_PORT}"), Some(parsed))
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

    if !hello.armed {
        return Err("The phone answered but 'Allow connection' is off. Turn it on in the NexLink app on your phone, then press Connect again.".to_string());
    }
    Ok((stream, hello, phone_ip))
}

/// The Connect button: reach the phone, then (Windows) start the real
/// tunnel. Runs on a blocking thread — the handshake and the adapter
/// setup both do blocking I/O.
#[tauri::command]
async fn connect(app: tauri::AppHandle, transport: String, address: String) -> Result<String, String> {
    // Clone the *inner* state (Arcs) — `app.state()` only borrows `app`,
    // which would not live long enough for `spawn_blocking`.
    let state = (*app.state::<TunnelState>()).clone();
    tauri::async_runtime::spawn_blocking(move || connect_blocking(&state, &transport, &address))
        .await
        .map_err(|e| format!("internal error: {e}"))?
}

fn connect_blocking(state: &TunnelState, transport: &str, address: &str) -> Result<String, String> {
    if state.inner.lock().unwrap().is_some() {
        return Err("Already connected — press Disconnect first.".to_string());
    }
    state.last_error.lock().unwrap().take();

    let (link, hello, phone_ip) = reach_phone(transport, address)?;

    #[cfg(windows)]
    {
        start_tunnel(state, link, hello, transport, phone_ip)
    }
    #[cfg(not(windows))]
    {
        let _ = (link, phone_ip);
        Err(format!(
            "Phone found: {} — armed and ready. But the tunnel only runs on the Windows build of NexLink; this build can only check the phone.",
            hello.phone_name
        ))
    }
}

/// Open the adapter, install the routes, and run the engine on its own
/// thread. The engine is created *inside* that thread: `Engine` holds
/// `Rc` state and is `!Send`, so it can never cross a thread boundary.
#[cfg(windows)]
fn start_tunnel(
    state: &TunnelState,
    link: TcpStream,
    hello: nxcore::engine::HelloAckInfo,
    transport: &str,
    phone_ip: Option<Ipv4Addr>,
) -> Result<String, String> {
    use nxcore::engine::Engine;
    use nxcore::Ipv4Address;
    use wintun_backend::{WintunDevice, GATEWAY_ADDRESS};

    if !routes::is_elevated() {
        return Err("NexLink must run as administrator to create the virtual adapter and add routes. Right-click NexLink → Run as administrator, then press Connect again.".to_string());
    }

    let (device, channels) = WintunDevice::open()?;
    let tunnel_routes = match routes::install(transport, phone_ip) {
        Ok(r) => r,
        Err(e) => {
            device.stop();
            return Err(e);
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let last_error = Arc::clone(&state.last_error);
    let summary = format!("{transport} · {}", hello.phone_name);
    let thread = std::thread::Builder::new()
        .name("nexlink-engine".to_string())
        .spawn(move || {
            // The engine lives and dies on this thread.
            let gateway = GATEWAY_ADDRESS.octets();
            let result = (|| -> std::io::Result<()> {
                let mut engine = Engine::new(
                    channels.to_engine_rx,
                    channels.from_engine_tx,
                    link,
                    Ipv4Address::new(gateway[0], gateway[1], gateway[2], gateway[3]),
                )?;
                engine.run(thread_stop)
            })();
            if let Err(e) = &result {
                *last_error.lock().unwrap() = Some(e.to_string());
            }
            // Teardown, always: routes first so traffic stops entering
            // the adapter, then the adapter itself. (On a clean
            // disconnect the main thread has already set `stop` and is
            // joining us; on a dead link this is what restores the PC's
            // normal routing instead of blackholing it.)
            tunnel_routes.remove();
            device.stop();
        });
    let thread = match thread {
        Ok(t) => t,
        // Practically unreachable (OS thread creation failure); the
        // device and routes are dropped with the closure, so this path
        // leaks a live adapter — noted, not hidden.
        Err(e) => return Err(format!("Could not start the engine thread: {e}")),
    };

    state.inner.lock().unwrap().replace(ActiveTunnel { stop, thread, summary });
    Ok(format!(
        "Connected via {transport} to {} — all PC traffic now goes through your phone (adapter 10.77.0.2, gateway 10.77.0.1). Press Disconnect to stop.",
        hello.phone_name
    ))
}

/// The Disconnect button: stop the engine, remove the routes, stop the
/// adapter. Blocking (it joins the engine thread), so it runs off the
/// async runtime.
#[tauri::command]
async fn disconnect(app: tauri::AppHandle) -> Result<String, String> {
    let state = (*app.state::<TunnelState>()).clone();
    tauri::async_runtime::spawn_blocking(move || state.stop_tunnel())
        .await
        .map_err(|e| format!("internal error: {e}"))
}

/// Polled by the window while connected (`connected|<summary>`,
/// `dead|<error>`, `disconnected`, `disconnected|<last error>`), so a
/// link that dies on its own shows up in the UI without a click.
#[tauri::command]
fn tunnel_status(state: tauri::State<TunnelState>) -> String {
    let guard = state.inner.lock().unwrap();
    match guard.as_ref() {
        Some(t) if t.thread.is_finished() => {
            let err = state
                .last_error
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| "the link closed".to_string());
            format!("dead|{err}")
        }
        Some(t) => format!("connected|{}", t.summary),
        None => match state.last_error.lock().unwrap().clone() {
            Some(e) => format!("disconnected|{e}"),
            None => "disconnected".to_string(),
        },
    }
}

fn main() {
    tauri::Builder::default()
        .manage(TunnelState::new())
        .invoke_handler(tauri::generate_handler![connect, disconnect, tunnel_status])
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
        .build(tauri::generate_context!())
        .expect("error while building NexLink")
        .run(|app: &tauri::AppHandle, event: RunEvent| {
            // Quitting (tray menu → Exit) must tear the tunnel down
            // first: stop the engine, remove the routes, stop the
            // adapter — otherwise the PC keeps routing into a dead
            // tunnel (or a stale adapter) after NexLink is gone.
            if let RunEvent::ExitRequested { .. } = event {
                app.state::<TunnelState>().stop_tunnel();
            }
        });
}
