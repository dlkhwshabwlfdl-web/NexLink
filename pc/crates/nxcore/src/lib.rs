//! NexLink core library: the NXLP wire protocol and the PC-side relay
//! engine (user-space TCP/IP stack + flow translation). See
//! `ARCHITECTURE.md` at the repository root for the full design.

pub mod engine;
pub mod proto;

/// Re-exported so consumers (the tray app, nxpump) don't need a direct
/// smoltcp dependency just to name an IPv4 address.
pub use smoltcp::wire::Ipv4Address;

/// The one MTU for the whole data path: the Wintun adapter, the smoltcp
/// device inside the engine, and every test double all use this value.
///
/// v0.2.1 shipped with the engine at 1500 and the adapter at 1400, so
/// every full-size packet the stack emitted was silently discarded by
/// Windows — handshakes and keepalives passed, bulk data never did.
/// There must never be a second MTU value in the data path again.
pub const LINK_MTU: usize = 1400;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

static LOG_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

/// Install the always-on log file (the tray app points this at
/// `%APPDATA%/NexLink/nexlink.log`). Lifecycle events logged through
/// [`nxlog`] are appended there whether or not `NXLOG` is set, so a
/// failed run on a user's PC always leaves a diagnosable trace. A file
/// that has grown past ~5 MiB is truncated first — one bounded log,
/// rotated by replacement, is enough for diagnosis.
pub fn set_log_file(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let truncate = std::fs::metadata(path).map(|m| m.len() > 5 * 1024 * 1024).unwrap_or(false);
    let file = OpenOptions::new().create(true).append(!truncate).write(truncate).open(path)?;
    let _ = LOG_FILE.set(Mutex::new(file));
    Ok(())
}

fn log_line(msg: &str) {
    if let Some(file) = LOG_FILE.get() {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(mut f) = file.lock() {
            let _ = writeln!(f, "[{secs}] {msg}");
            let _ = f.flush();
        }
    }
}

/// Lifecycle logging: flow setup/teardown, probe results, link death,
/// connect stages. Goes to the log file installed by [`set_log_file`]
/// (always, once installed) and to stderr when `NXLOG` is set.
pub fn nxlog(msg: String) {
    if std::env::var_os("NXLOG").is_some() {
        eprintln!("[nxcore] {msg}");
    }
    log_line(&msg);
}

/// Verbose per-packet tracing for development only: stderr, and only
/// when `NXLOG` is set. Never written to the log file — at packet rate
/// it would drown the lifecycle events that matter.
pub fn nxdebug(msg: String) {
    if std::env::var_os("NXLOG").is_some() {
        eprintln!("[nxcore] {msg}");
    }
}
