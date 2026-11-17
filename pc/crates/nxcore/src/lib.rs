//! NexLink core library: the NXLP wire protocol and the PC-side relay
//! engine (user-space TCP/IP stack + flow translation). See
//! `ARCHITECTURE.md` at the repository root for the full design.

pub mod engine;
pub mod proto;

/// Re-exported so consumers (the tray app, nxpump) don't need a direct
/// smoltcp dependency just to name an IPv4 address.
pub use smoltcp::wire::Ipv4Address;

/// Debug logging, enabled by setting the `NXLOG` environment variable.
/// Used by the engine to trace flow setup and data movement while
/// developing; silent in normal runs.
pub fn nxlog(msg: String) {
    if std::env::var_os("NXLOG").is_some() {
        eprintln!("[nxcore] {msg}");
    }
}
