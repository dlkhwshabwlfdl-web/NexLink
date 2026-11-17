//! Wintun adapter backend (Windows only) — backlog item 1.
//!
//! Creates the "NexLink" Wintun adapter at 10.77.0.2/24 (gateway
//! 10.77.0.1) and pumps packets between the adapter's ring buffer and the
//! two `std::sync::mpsc` channels `nxcore::engine::Engine::new` expects:
//!
//! ```text
//! adapter ──receive_blocking──► to_engine_rx ──► Engine (smoltcp stack)
//! adapter ◄──send_packet────── from_engine_tx ◄── Engine
//! ```
//!
//! No UI wiring yet (that is backlog item 2): this module only proves the
//! adapter can be created, addressed and pumped. `WintunDevice::open()`
//! returns the device handle plus the channel ends; the caller hands the
//! channels to `Engine::new` and calls `device.stop()` when done.
//!
//! Requirements on the machine, both documented here because they bite at
//! runtime rather than at compile time:
//! * `wintun.dll` must sit next to the exe — it is bundled by the
//!   installer (backlog item 3). `wintun::load()` searches the exe's
//!   directory first.
//! * The app must run elevated (administrator): creating the adapter and
//!   setting its address (via `netsh`) both need it.
//!
//! The adapter is created with a fresh random GUID each run; if an adapter
//! named "NexLink" already exists (e.g. left behind by a crashed run) it
//! is opened and reused instead. The address is (re-)applied on every
//! open, so a reused adapter always ends up at 10.77.0.2/24.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use wintun::{Adapter, Session};

/// Name of the virtual adapter as it appears in Windows' network list.
pub const ADAPTER_NAME: &str = "NexLink";
/// Tunnel type shown in the adapter's details.
pub const TUNNEL_TYPE: &str = "NexLink";
/// Address of this end of the tunnel (the PC side).
pub const ADAPTER_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
/// Netmask for the /24 tunnel network.
pub const ADAPTER_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
/// The phone side of the tunnel. The engine also uses it as its default
/// route ("routed locally" — see `nxcore::engine::Engine::new`).
pub const GATEWAY_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
/// MTU of the virtual adapter. 1400 leaves headroom for the NXLP/TCP
/// encapsulation between the PC and the phone.
pub const ADAPTER_MTU: usize = 1400;
/// Ring buffer size per direction. Must be a power of two between
/// `wintun::MIN_RING_CAPACITY` (128 KiB) and `wintun::MAX_RING_CAPACITY`
/// (64 MiB); 4 MiB holds ~2800 full-size packets per direction.
const RING_CAPACITY: u32 = 0x400_000;

/// The two channel ends the engine consumes, in exactly the shape
/// `Engine::new(dev_rx, dev_tx, link, gateway)` takes:
/// * `to_engine_rx` — raw IP packets read from the adapter.
/// * `from_engine_tx` — raw IP packets the engine emits, written to the
///   adapter.
pub struct WintunChannels {
    pub to_engine_rx: Receiver<Vec<u8>>,
    pub from_engine_tx: Sender<Vec<u8>>,
}

/// A live Wintun adapter + session with its two pump threads.
///
/// The channels live in [`WintunChannels`] (returned alongside this
/// handle by [`WintunDevice::open`]); this handle owns the session and
/// the threads, and `stop()` ends them. It has no `Drop` impl on purpose:
/// dropping it while the engine still holds the channels would kill the
/// pump mid-tunnel — shutdown is always explicit, via `stop()`.
pub struct WintunDevice {
    session: Arc<Session>,
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

impl WintunDevice {
    /// Load `wintun.dll`, create (or reopen) the "NexLink" adapter,
    /// address it 10.77.0.2/24 with gateway 10.77.0.1, start a session and
    /// spawn the two pump threads.
    pub fn open() -> Result<(WintunDevice, WintunChannels), String> {
        // SAFETY: wintun.dll is the official WinTun driver library, shipped
        // next to our exe by the installer. Loading it is inherently a
        // trust-the-dll operation; see `wintun::load`'s docs.
        let wintun = unsafe { wintun::load() }.map_err(|e| {
            format!(
                "Could not load wintun.dll ({e}). Make sure wintun.dll sits next to NexLink.exe \
                 (the installer bundles it) and the app runs as administrator."
            )
        })?;

        // A previous run may have left the adapter behind; reuse it rather
        // than failing. Either way the address is re-applied below.
        let adapter = match Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None) {
            Ok(adapter) => adapter,
            Err(create_err) => Adapter::open(&wintun, ADAPTER_NAME).map_err(|_| {
                format!(
                    "Could not create the '{ADAPTER_NAME}' adapter ({create_err}). \
                     The app must run as administrator."
                )
            })?,
        };

        // `netsh interface ipv4 set address` — needs elevation.
        adapter
            .set_network_addresses_tuple(
                IpAddr::V4(ADAPTER_ADDRESS),
                IpAddr::V4(ADAPTER_NETMASK),
                Some(IpAddr::V4(GATEWAY_ADDRESS)),
            )
            .map_err(|e| format!("Could not set the adapter address to {ADAPTER_ADDRESS}/24 ({e}). The app must run as administrator."))?;
        adapter
            .set_mtu(ADAPTER_MTU)
            .map_err(|e| format!("Could not set the adapter MTU to {ADAPTER_MTU} ({e})."))?;

        let session = Arc::new(
            adapter
                .start_session(RING_CAPACITY)
                .map_err(|e| format!("Could not start the Wintun session ({e})."))?,
        );

        let (to_engine_tx, to_engine_rx) = channel::<Vec<u8>>();
        let (from_engine_tx, from_engine_rx) = channel::<Vec<u8>>();
        let stop = Arc::new(AtomicBool::new(false));

        // Adapter -> engine. `receive_blocking` waits on the driver's read
        // event and returns `Err(ShuttingDown)` once `session.shutdown()`
        // is called, so this thread always exits on `stop()`.
        let read_session = Arc::clone(&session);
        let read_stop = Arc::clone(&stop);
        let read_handle = std::thread::spawn(move || {
            while !read_stop.load(Ordering::Relaxed) {
                match read_session.receive_blocking() {
                    Ok(packet) => {
                        // The engine end is gone: nothing left to pump to.
                        if to_engine_tx.send(packet.bytes().to_vec()).is_err() {
                            return;
                        }
                    }
                    Err(_) => return, // session shutting down
                }
            }
        });

        // Engine -> adapter. `recv_timeout` lets the thread notice `stop`
        // even while the engine holds the sender open; packets larger
        // than the ring's u16 packet size cannot exist on the wire for
        // IPv4 (max 65535 bytes) but are dropped defensively instead of
        // truncating.
        let write_session = Arc::clone(&session);
        let write_stop = Arc::clone(&stop);
        let write_handle = std::thread::spawn(move || loop {
            if write_stop.load(Ordering::Relaxed) {
                return;
            }
            match from_engine_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(pkt) => {
                    let Ok(size) = u16::try_from(pkt.len()) else {
                        continue;
                    };
                    let Ok(mut out) = write_session.allocate_send_packet(size) else {
                        return; // session gone
                    };
                    out.bytes_mut().copy_from_slice(&pkt);
                    write_session.send_packet(out);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
        });

        let device = WintunDevice { session, stop, handles: vec![read_handle, write_handle] };
        let channels = WintunChannels { to_engine_rx, from_engine_tx };
        Ok((device, channels))
    }

    /// Stop the pump threads and end the session. The adapter itself is
    /// left in place (Windows keeps it for the next run, which reopens
    /// it); deleting it on every disconnect would force a driver
    /// re-install prompt cycle and is backlog item 2's call, not this
    /// module's.
    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        // Unblocks the read thread's `receive_blocking()`.
        let _ = self.session.shutdown();
        for handle in self.handles {
            let _ = handle.join();
        }
    }
}
