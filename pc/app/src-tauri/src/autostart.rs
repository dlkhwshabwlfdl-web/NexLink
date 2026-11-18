//! "Start with Windows" (backlog item 3).
//!
//! Writes the exe path into the user's Run key
//! (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value name
//! "NexLink") so Windows launches NexLink at logon. It goes through
//! `reg.exe` via `std::process` — the same style as `routes.rs`, so no
//! extra crate is needed — and only exit codes are trusted for
//! add/delete; the read parses the value line with
//! [`netutil::parse_reg_query_value`] (unit-tested on every platform).
//!
//! Known caveat, documented in the UI and the README rather than hidden:
//! the app's manifest requests administrator elevation, so with
//! autostart on, Windows shows a UAC prompt at every logon. A Task
//! Scheduler entry ("run with highest privileges") would avoid the
//! prompt; that is a later improvement, not this item.

use std::process::{Command, Stdio};

use crate::netutil;

/// The Run key for the current user (no admin rights needed to write
/// it — HKCU, not HKLM).
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
/// Value name inside the Run key.
const VALUE_NAME: &str = "NexLink";

/// The current exe path, double-quoted so paths with spaces (e.g.
/// `C:\Program Files\NexLink\NexLink.exe`) survive as one command.
fn exe_command() -> Result<String, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Could not find the NexLink exe path ({e})."))?;
    Ok(format!("\"{}\"", exe.display()))
}

fn run_reg(args: &[&str]) -> Result<String, String> {
    let output = Command::new("reg")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("could not run reg.exe ({e})"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// Is autostart on *for this exe*? True only when the Run value exists
/// and points at the exe that is currently running — a stale value left
/// by a moved or older install counts as off (turning the checkbox on
/// overwrites it).
pub fn is_enabled() -> Result<bool, String> {
    let wanted = exe_command()?;
    match run_reg(&["query", RUN_KEY, "/v", VALUE_NAME]) {
        Ok(out) => Ok(netutil::parse_reg_query_value(&out, VALUE_NAME).as_deref() == Some(wanted.as_str())),
        // `reg query` exits non-zero when the value (or the key) does
        // not exist — that just means autostart is off, not an error.
        Err(_) => Ok(false),
    }
}

/// Turn autostart on (write the Run value) or off (delete it).
pub fn set_enabled(enabled: bool) -> Result<(), String> {
    if enabled {
        let command = exe_command()?;
        run_reg(&["add", RUN_KEY, "/v", VALUE_NAME, "/t", "REG_SZ", "/d", &command, "/f"])
            .map_err(|e| format!("Could not turn on 'Start with Windows' ({e})"))?;
    } else {
        // Deleting a value that is already gone is not an error.
        let _ = run_reg(&["delete", RUN_KEY, "/v", VALUE_NAME, "/f"]);
    }
    Ok(())
}
