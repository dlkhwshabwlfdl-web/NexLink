//! The NexLink relay engine (PC side).
//!
//! The engine sits between a packet device (Wintun on Windows, a TUN device
//! on Linux) and one NXLP link stream to the phone:
//!
//! ```text
//! device packets ─► smoltcp stack (impersonates every destination)
//!                       │  byte streams / datagrams
//!                       ▼
//!                   NXLP flows ─► phone ─► phone sockets ─► internet / VPN
//! ```
//!
//! Connections from PC apps are accepted by the stack immediately (the
//! handshake completes locally), while the phone dials the real destination.
//! If the phone refuses (not armed / unreachable), the stack socket is reset.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken as PhyRxToken, TxToken as PhyTxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, UdpPacket};

use crate::proto::*;

// ---------------------------------------------------------------------------
// Packet device plumbing: the harness pumps a real TUN/Wintun device into
// channels; the engine feeds smoltcp from a shared queue so it can sniff
// packets (for new flows) before the stack sees them.
// ---------------------------------------------------------------------------

type SharedQueue = Rc<RefCell<VecDeque<Vec<u8>>>>;

struct ChanDevice {
    queue: SharedQueue,
    tx: Sender<Vec<u8>>,
}

struct RxTok(Vec<u8>);
struct TxTok(Sender<Vec<u8>>);

impl PhyRxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl PhyTxToken for TxTok {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let _ = self.0.send(buf);
        r
    }
}

impl Device for ChanDevice {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok;

    fn receive(&mut self, _ts: Instant) -> Option<(RxTok, TxTok)> {
        let pkt = self.queue.borrow_mut().pop_front()?;
        Some((RxTok(pkt), TxTok(self.tx.clone())))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<TxTok> {
        Some(TxTok(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        // The shared link MTU — must match the Wintun adapter exactly
        // (see `crate::LINK_MTU`; the 1500/1400 split was the v0.2.1
        // "Connected but nothing loads" bug).
        caps.max_transmission_unit = crate::LINK_MTU;
        caps
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

pub struct HelloAckInfo {
    pub armed: bool,
    pub phone_name: String,
}

/// Send HELLO and wait for HELLO_ACK. The stream must be in blocking mode;
/// a read timeout is applied for the duration of the handshake.
pub fn client_handshake(stream: &mut TcpStream, client_name: &str) -> io::Result<HelloAckInfo> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    Frame::Hello { version: PROTO_VERSION, name: client_name.to_string() }.encode(&mut buf);
    stream.write_all(&buf)?;
    let mut reader = FrameReader::new();
    let mut chunk = [0u8; 4096];
    loop {
        match reader.next_frame()? {
            Some(Frame::HelloAck { armed, name }) => {
                stream.set_read_timeout(None)?;
                stream.set_write_timeout(None)?;
                return Ok(HelloAckInfo { armed, phone_name: name });
            }
            Some(_) => continue,
            None => {
                let n = stream.read(&mut chunk)?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "phone closed the link during handshake"));
                }
                reader.feed(&chunk[..n]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Live count of user DATA bytes that crossed the tunnel, shared with
/// whoever runs the engine (the tray app shows them in its status line;
/// a "Connected" with both counters stuck at zero is exactly the
/// failure v0.2.1 hid). `up` = PC → phone, `down` = phone → PC.
/// Handshake, keepalive and connect-probe bytes are not counted — only
/// payload of flows the stack serviced.
#[derive(Clone, Default)]
pub struct TrafficCounters {
    pub up: Arc<AtomicU64>,
    pub down: Arc<AtomicU64>,
}

impl TrafficCounters {
    pub fn new() -> Self {
        Self::default()
    }

    /// (down, up) snapshot.
    pub fn snapshot(&self) -> (u64, u64) {
        (self.down.load(Ordering::Relaxed), self.up.load(Ordering::Relaxed))
    }
}

/// The two connect-probe stages, in order. The app maps these to its
/// "Verifying DNS…" / "Verifying traffic…" status texts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStage {
    Dns,
    Traffic,
}

enum ProbeEvent {
    OpenOk,
    OpenErr(u8),
    Data(Vec<u8>),
    Closed,
    Timeout,
}

/// Phone -> app backlog per flow at which read_link pauses and lets the
/// stack drain (backpressure) instead of accepting more link data.
const PENDING_HIGH_WATER: usize = 4 * 1024 * 1024;
/// How long a flow's backlog may sit at the high-water mark with ZERO
/// drain progress before the flow is reset. This is what bounds memory
/// for an app that never reads: backpressure alone would pin the
/// backlog at the high-water mark forever. A flow that is draining at
/// any speed refreshes its progress timestamp on every flush and is
/// never reset — the pre-v0.3.1 behaviour (reset the instant the cap
/// was crossed) could not tell the two apart and killed every bulk
/// transfer over the cap.
const PENDING_STALL_RESET: Duration = Duration::from_secs(10);
/// Last-resort backlog bound, far above anything backpressure allows in
/// practice (~high-water + one read chunk). Only a wedged app that never
/// drains can reach it; the flow is then reset — and the reset now
/// actually reaches the app (see `rst_pending`).
const PENDING_HARD_CAP: usize = 16 * 1024 * 1024;

struct TcpFlow {
    handle: SocketHandle,
    tuple: (Ipv4Address, u16, Ipv4Address, u16), // src ip, src port, dst ip, dst port
    open: bool,
    pending: VecDeque<Vec<u8>>,
    fin_to_phone: bool,
    /// The phone half-closed (sent Close FIN). The stack socket must NOT be
    /// close()d until `pending` has been flushed to the app: smoltcp
    /// refuses send_slice after close(), which would silently drop the
    /// tail of the stream whenever Data and Close arrive in one batch.
    fin_from_phone: bool,
    fin_sent: bool,
    /// The phone reset this flow (Close RST / OpenErr) or the backlog hard
    /// cap fired. The stack socket is NOT torn down here: smoltcp emits
    /// the RST to the app from a Closed socket on the next iface poll, so
    /// service_flows aborts the socket and the sweep removes it one pass
    /// later. (Aborting + removing in the frame handler, as before, ate
    /// the RST entirely — the app hung on a phantom connection.)
    rst_pending: bool,
    /// Last time the flush moved at least one byte from `pending` into
    /// the stack socket. Drives the stall reset (PENDING_STALL_RESET).
    last_progress: StdInstant,
}

impl TcpFlow {
    fn pending_len(&self) -> usize {
        self.pending.iter().map(|d| d.len()).sum()
    }
}

struct UdpFlow {
    handle: SocketHandle,
    key: (Ipv4Address, u16, Ipv4Address, u16), // src ip, src port, dst ip, dst port
    app: IpEndpoint, // the PC app endpoint that "owns" this association
    last_seen: StdInstant,
}

pub struct Engine {
    iface: Interface,
    device: ChanDevice,
    dev_rx: Receiver<Vec<u8>>,
    queue: SharedQueue,
    sockets: SocketSet<'static>,
    link: TcpStream,
    reader: FrameReader,
    out: Vec<u8>,
    tcp_flows: HashMap<u32, TcpFlow>,
    tcp_by_tuple: HashMap<(Ipv4Address, u16, Ipv4Address, u16), u32>,
    udp_flows: HashMap<u32, UdpFlow>,
    udp_by_key: HashMap<(Ipv4Address, u16, Ipv4Address, u16), u32>,
    next_flow: u32,
    last_ping: StdInstant,
    last_rx: StdInstant,
    last_debug_dump: StdInstant,
    counters: TrafficCounters,
}

impl Engine {
    /// `dev_rx` yields raw IP packets from the device; packets the stack
    /// emits are sent on `dev_tx`. `link` must already be handshaken and is
    /// switched to non-blocking mode here.
    pub fn new(
        dev_rx: Receiver<Vec<u8>>,
        dev_tx: Sender<Vec<u8>>,
        link: TcpStream,
        gateway: Ipv4Address,
        counters: TrafficCounters,
    ) -> io::Result<Engine> {
        link.set_nonblocking(true)?;
        let queue: SharedQueue = Rc::new(RefCell::new(VecDeque::new()));
        let mut device = ChanDevice { queue: queue.clone(), tx: dev_tx };
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(gateway), 24));
        });
        // The stack impersonates *every* destination the PC talks to, so it
        // must accept packets for any address. (Registering each destination
        // as a /32 instead would hit smoltcp's interface address cap of 2.)
        // AnyIP only accepts a packet when a route lookup for its
        // destination resolves to one of the interface's own addresses —
        // hence the default route via the gateway itself ("routed locally").
        iface.set_any_ip(true);
        let _ = iface.routes_mut().add_default_ipv4_route(gateway);
        let engine = Engine {
            iface,
            device,
            dev_rx,
            queue,
            sockets: SocketSet::new(vec![]),
            link,
            reader: FrameReader::new(),
            out: Vec::with_capacity(64 * 1024),
            tcp_flows: HashMap::new(),
            tcp_by_tuple: HashMap::new(),
            udp_flows: HashMap::new(),
            udp_by_key: HashMap::new(),
            next_flow: 1,
            last_ping: StdInstant::now(),
            last_rx: StdInstant::now(),
            last_debug_dump: StdInstant::now(),
            counters,
        };
        Ok(engine)
    }

    pub fn run(&mut self, stop: Arc<AtomicBool>) -> io::Result<()> {
        while !stop.load(Ordering::Relaxed) {
            let mut did_work = false;

            // 1. Sniff packets that arrived since the last tick, before the
            //    stack processes them in step 3.
            while let Ok(pkt) = self.dev_rx.try_recv() {
                self.sniff(&pkt);
                self.queue.borrow_mut().push_back(pkt);
                did_work = true;
            }

            // 2. Read and handle link frames.
            did_work |= self.read_link()?;

            // 3. Let the stack process packets.
            let now = Instant::now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            if self.iface.poll_delay(now, &self.sockets) == Some(smoltcp::time::Duration::ZERO) {
                did_work = true;
            }

            // 4. Move data between stack sockets and flows.
            did_work |= self.service_flows();

            // 5. Flush pending link bytes.
            did_work |= self.flush_link()?;

            // 6. Keepalive + link liveness.
            if self.last_debug_dump.elapsed() > Duration::from_secs(2) {
                self.last_debug_dump = StdInstant::now();
                for (id, f) in self.tcp_flows.iter() {
                    let socket = self.sockets.get::<tcp::Socket>(f.handle);
                    crate::nxdebug(format!(
                        "tcp flow {id}: tuple={:?} state={:?} open={}",
                        f.tuple,
                        socket.state(),
                        f.open
                    ));
                }
                for (id, f) in self.udp_flows.iter() {
                    let socket = self.sockets.get::<udp::Socket>(f.handle);
                    crate::nxdebug(format!(
                        "udp flow {id}: endpoint={:?} can_recv={} recv_queue={}",
                        socket.endpoint(),
                        socket.can_recv(),
                        socket.recv_queue()
                    ));
                }
            }
            if self.last_ping.elapsed() > Duration::from_secs(20) {
                self.queue_frame(&Frame::Ping);
                self.last_ping = StdInstant::now();
            }
            if self.last_rx.elapsed() > Duration::from_secs(60) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "no frames from the phone for 60s — link is dead"));
            }

            if !did_work {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        self.queue_frame(&Frame::Bye);
        let _ = self.flush_link();
        Ok(())
    }

    // -- connect probes -----------------------------------------------------
    //
    // "Connected" is gated on traffic, not on the handshake (the PdaNet
    // lesson; v0.2.1 asserted Connected after thread spawn and a dead
    // data path looked identical to a working one). Before `run`, the
    // caller drives these probes over the engine's own flow machinery:
    // a real DNS query through the phone's interception, and a real TCP
    // open the phone must complete. A failure names its stage.

    /// One end-to-end verification through the tunnel, run on the
    /// handshaken link before the main loop starts. `on_stage` is
    /// called as each stage begins (the app turns it into its
    /// "Verifying DNS…" / "Verifying traffic…" status text). Errors
    /// are complete user-facing messages prefixed with the stage name.
    pub fn run_probes(
        &mut self,
        stop: &AtomicBool,
        on_stage: &mut dyn FnMut(ProbeStage),
    ) -> Result<(), String> {
        self.probe_dns(stop, on_stage)
            .map_err(|e| prefix_stage("DNS check failed", e))?;
        self.probe_traffic(stop, on_stage)
            .map_err(|e| prefix_stage("Traffic check failed", e))?;
        Ok(())
    }

    fn alloc_flow(&mut self) -> u32 {
        let flow = self.next_flow;
        self.next_flow += 1;
        flow
    }

    fn probe_dns(
        &mut self,
        stop: &AtomicBool,
        on_stage: &mut dyn FnMut(ProbeStage),
    ) -> Result<(), String> {
        on_stage(ProbeStage::Dns);
        crate::nxlog("probe: DNS check — querying example.com via 8.8.8.8:53".to_string());
        // Any fixed id works; the response must echo it.
        let txid: u16 = 0x4E58;
        let flow = self.alloc_flow();
        self.queue_frame(&Frame::Open { flow, proto: PROTO_UDP, ip: [8, 8, 8, 8], port: 53 });
        self.queue_frame(&Frame::Data { flow, data: build_dns_query(txid) });
        self.flush_link()
            .map_err(|e| format!("DNS check failed: could not send the test query ({e})"))?;
        let deadline = StdInstant::now() + Duration::from_secs(12);
        loop {
            match self.wait_probe_event(stop, flow, deadline)? {
                ProbeEvent::Data(data) => {
                    if valid_dns_response(&data, txid) {
                        crate::nxlog(format!(
                            "probe: DNS check OK ({}-byte answer)",
                            data.len()
                        ));
                        self.queue_frame(&Frame::Close { flow, flags: CLOSE_FIN });
                        let _ = self.flush_link();
                        return Ok(());
                    }
                    // Not our answer (or a malformed one): keep waiting
                    // until the deadline — the real one may follow.
                }
                ProbeEvent::OpenOk => {}
                ProbeEvent::OpenErr(code) => {
                    return Err(format!(
                        "DNS check failed: the phone refused the test DNS flow (error {code})"
                    ));
                }
                ProbeEvent::Closed => {
                    return Err(
                        "DNS check failed: the phone closed the test flow without answering"
                            .to_string(),
                    );
                }
                ProbeEvent::Timeout => {
                    return Err(
                        "DNS check failed: no answer came back through the phone within 12 seconds"
                            .to_string(),
                    );
                }
            }
        }
    }

    fn probe_traffic(
        &mut self,
        stop: &AtomicBool,
        on_stage: &mut dyn FnMut(ProbeStage),
    ) -> Result<(), String> {
        on_stage(ProbeStage::Traffic);
        crate::nxlog("probe: traffic check — opening a TCP flow to 1.1.1.1:443".to_string());
        let flow = self.alloc_flow();
        self.queue_frame(&Frame::Open { flow, proto: PROTO_TCP, ip: [1, 1, 1, 1], port: 443 });
        self.flush_link()
            .map_err(|e| format!("Traffic check failed: could not open the test flow ({e})"))?;
        // The phone's own connect timeout is 10 s; allow slack on top.
        let deadline = StdInstant::now() + Duration::from_secs(15);
        loop {
            match self.wait_probe_event(stop, flow, deadline)? {
                ProbeEvent::OpenOk => {
                    crate::nxlog("probe: traffic check OK (phone connected to 1.1.1.1:443)".to_string());
                    self.queue_frame(&Frame::Close { flow, flags: CLOSE_RST });
                    let _ = self.flush_link();
                    return Ok(());
                }
                ProbeEvent::OpenErr(code) => {
                    return Err(format!(
                        "Traffic check failed: the phone could not connect to 1.1.1.1:443 (error {code})"
                    ));
                }
                ProbeEvent::Closed => {
                    return Err(
                        "Traffic check failed: the phone closed the test flow".to_string()
                    );
                }
                ProbeEvent::Data(_) => {}
                ProbeEvent::Timeout => {
                    return Err(
                        "Traffic check failed: the phone did not confirm a connection to 1.1.1.1:443 within 15 seconds"
                            .to_string(),
                    );
                }
            }
        }
    }

    /// Pump the link until one event for `flow` arrives or the deadline
    /// passes. Frames for other flows cannot exist yet (the probes run
    /// before any user flow), so anything else is answered if it needs
    /// an answer (Ping → Pong) and otherwise dropped.
    fn wait_probe_event(
        &mut self,
        stop: &AtomicBool,
        flow: u32,
        deadline: StdInstant,
    ) -> Result<ProbeEvent, String> {
        let mut chunk = [0u8; 16 * 1024];
        loop {
            if stop.load(Ordering::Relaxed) {
                return Err("Connection cancelled".to_string());
            }
            if StdInstant::now() >= deadline {
                return Ok(ProbeEvent::Timeout);
            }
            match self.link.read(&mut chunk) {
                Ok(0) => {
                    return Err("the phone closed the link during verification".to_string());
                }
                Ok(n) => {
                    self.last_rx = StdInstant::now();
                    self.reader.feed(&chunk[..n]);
                    while let Some(frame) = self
                        .reader
                        .next_frame()
                        .map_err(|e| format!("verification failed: {e}"))?
                    {
                        match frame {
                            Frame::Ping => {
                                self.queue_frame(&Frame::Pong);
                                self.flush_link()
                                    .map_err(|e| format!("verification failed: {e}"))?;
                            }
                            Frame::OpenOk { flow: f } if f == flow => {
                                return Ok(ProbeEvent::OpenOk);
                            }
                            Frame::OpenErr { flow: f, code } if f == flow => {
                                return Ok(ProbeEvent::OpenErr(code));
                            }
                            Frame::Data { flow: f, data } if f == flow => {
                                return Ok(ProbeEvent::Data(data));
                            }
                            Frame::Close { flow: f, .. } if f == flow => {
                                return Ok(ProbeEvent::Closed);
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(format!("verification failed: link error ({e})"));
                }
            }
        }
    }

    // -- packet sniffing ----------------------------------------------------

    fn sniff(&mut self, pkt: &[u8]) {
        let Ok(ip) = Ipv4Packet::new_checked(pkt) else { return };
        let src = ip.src_addr();
        let dst = ip.dst_addr();
        match ip.next_header() {
            IpProtocol::Tcp => {
                let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else { return };
                if tcp.syn() && !tcp.ack() {
                    let tuple = (src, tcp.src_port(), dst, tcp.dst_port());
                    if !self.tcp_by_tuple.contains_key(&tuple) {
                        self.open_tcp_flow(tuple);
                    }
                }
            }
            IpProtocol::Udp => {
                let Ok(udp_pkt) = UdpPacket::new_checked(ip.payload()) else { return };
                let key = (src, udp_pkt.src_port(), dst, udp_pkt.dst_port());
                crate::nxdebug(format!("sniff udp {src}:{} -> {dst}:{}", key.1, key.3));
                if !self.udp_by_key.contains_key(&key) {
                    self.open_udp_flow(key);
                }
            }
            _ => {}
        }
    }

    fn open_tcp_flow(&mut self, tuple: (Ipv4Address, u16, Ipv4Address, u16)) {
        let (src, sport, dst, dport) = tuple;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 64 * 1024]),
            tcp::SocketBuffer::new(vec![0; 64 * 1024]),
        );
        socket.set_nagle_enabled(false);
        if let Err(e) = socket.listen(IpEndpoint::new(IpAddress::Ipv4(dst), dport)) {
            crate::nxlog(format!("open tcp flow FAILED listen {src}:{sport} -> {dst}:{dport}: {e:?}"));
            return;
        }
        let handle = self.sockets.add(socket);
        let flow = self.next_flow;
        self.next_flow += 1;
        crate::nxlog(format!("open tcp flow {flow}: {src}:{sport} -> {dst}:{dport}"));
        self.tcp_flows.insert(flow, TcpFlow { handle, tuple, open: false, pending: VecDeque::new(), fin_to_phone: false, fin_from_phone: false, fin_sent: false, rst_pending: false, last_progress: StdInstant::now() });
        self.tcp_by_tuple.insert(tuple, flow);
        let _ = (src, sport);
        self.queue_frame(&Frame::Open { flow, proto: PROTO_TCP, ip: dst.octets(), port: dport });
    }

    fn open_udp_flow(&mut self, key: (Ipv4Address, u16, Ipv4Address, u16)) {
        let (src, sport, dst, dport) = key;
        let mk_buffer = || {
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 64 * 1024])
        };
        let mut socket = udp::Socket::new(mk_buffer(), mk_buffer());
        if socket.bind(IpEndpoint::new(IpAddress::Ipv4(dst), dport)).is_err() {
            return;
        }
        let handle = self.sockets.add(socket);
        let flow = self.next_flow;
        self.next_flow += 1;
        self.udp_flows.insert(flow, UdpFlow {
            handle,
            key,
            app: IpEndpoint::new(IpAddress::Ipv4(src), sport),
            last_seen: StdInstant::now(),
        });
        self.udp_by_key.insert(key, flow);
        crate::nxlog(format!("open udp flow {flow}: {src}:{sport} -> {dst}:{dport}"));
        self.queue_frame(&Frame::Open { flow, proto: PROTO_UDP, ip: dst.octets(), port: dport });
    }

    // -- link I/O -----------------------------------------------------------

    fn queue_frame(&mut self, frame: &Frame) {
        frame.encode(&mut self.out);
    }

    fn flush_link(&mut self) -> io::Result<bool> {
        if self.out.is_empty() {
            return Ok(false);
        }
        match self.link.write(&self.out) {
            Ok(0) => Err(io::Error::new(io::ErrorKind::WriteZero, "link write returned 0")),
            Ok(n) => {
                self.out.drain(..n);
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn read_link(&mut self) -> io::Result<bool> {
        let mut chunk = [0u8; 64 * 1024];
        let mut any = false;
        loop {
            // Backpressure: once a flow's phone -> app backlog reaches
            // the high-water mark, stop reading the link and let the
            // stack drain the backlog first. The unread bytes stay in
            // the link socket's receive buffer, so ordinary TCP flow
            // control throttles the phone. (Resetting the flow here, as
            // the old cap did, killed every bulk transfer whose sender
            // burst past the cap faster than the app drained — i.e.
            // every download over ~4 MiB on a fast link.)
            if self.tcp_flows.values().any(|f| f.pending_len() >= PENDING_HIGH_WATER) {
                break;
            }
            match self.link.read(&mut chunk) {
                Ok(0) => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "phone closed the link"));
                }
                Ok(n) => {
                    any = true;
                    self.last_rx = StdInstant::now();
                    self.reader.feed(&chunk[..n]);
                    while let Some(frame) = self.reader.next_frame()? {
                        self.handle_frame(frame);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(any)
    }

    fn handle_frame(&mut self, frame: Frame) {
        match frame {
            Frame::OpenOk { flow } => {
                crate::nxlog(format!("open-ok flow {flow}"));
                if let Some(f) = self.tcp_flows.get_mut(&flow) {
                    f.open = true;
                }
            }
            Frame::OpenErr { flow, code } => {
                crate::nxlog(format!("open-err flow {flow} code {code}"));
                if let Some(f) = self.tcp_flows.get_mut(&flow) {
                    // The phone could not open the destination: reset the
                    // app-side connection so the app sees a refusal
                    // instead of hanging (deferred teardown, see
                    // rst_pending).
                    f.rst_pending = true;
                } else if let Some(f) = self.udp_flows.remove(&flow) {
                    self.udp_by_key.remove(&f.key);
                    self.sockets.remove(f.handle);
                }
            }
            Frame::Data { flow, data } => {
                self.counters.down.fetch_add(data.len() as u64, Ordering::Relaxed);
                // Backstop for the read_link backpressure: the backlog
                // can only approach this bound if the app never drains,
                // in which case the flow is reset (deferred teardown —
                // the sweep tells the phone, service_flows makes sure
                // the app actually sees the RST).
                let over_cap = match self.tcp_flows.get(&flow) {
                    Some(f) => f.pending_len() + data.len() > PENDING_HARD_CAP,
                    None => false,
                };
                if over_cap {
                    if let Some(f) = self.tcp_flows.get_mut(&flow) {
                        f.pending.clear();
                        f.rst_pending = true;
                    }
                    return;
                }
                if let Some(f) = self.tcp_flows.get_mut(&flow) {
                    f.pending.push_back(data);
                } else if let Some(f) = self.udp_flows.get_mut(&flow) {
                    f.last_seen = StdInstant::now();
                    let socket = self.sockets.get_mut::<udp::Socket>(f.handle);
                    let r = socket.send_slice(&data, f.app);
                    crate::nxdebug(format!("udp flow {flow}: send_slice {} bytes to {} -> {r:?}", data.len(), f.app));
                }
            }
            Frame::Close { flow, flags } => {
                if flags & CLOSE_RST != 0 {
                    if let Some(f) = self.tcp_flows.get_mut(&flow) {
                        // Deferred teardown (see rst_pending): the app
                        // must observe this reset, not a silent freeze.
                        f.rst_pending = true;
                    }
                } else if let Some(f) = self.tcp_flows.get_mut(&flow) {
                    // Phone sent everything and half-closed its side. Only
                    // record it here — service_flows closes the stack socket
                    // once every pending byte has been flushed to the app
                    // (closing earlier would make smoltcp refuse the data).
                    f.fin_from_phone = true;
                }
            }
            Frame::Ping => self.queue_frame(&Frame::Pong),
            Frame::Pong => {}
            Frame::Bye => {
                // Phone is going away; the read side will EOF and end the run.
            }
            Frame::Hello { .. } | Frame::HelloAck { .. } | Frame::Open { .. } => {}
        }
    }

    // -- socket servicing ---------------------------------------------------

    fn service_flows(&mut self) -> bool {
        let mut work = false;
        let mut frames: Vec<Frame> = Vec::new();

        // Flows whose stack socket was already Closed when this pass
        // began. A socket aborted during THIS pass (rst_pending below)
        // must survive until the next iface poll has emitted its RST to
        // the app, so teardown is decided from this snapshot, never from
        // a state observed mid-pass.
        let closed_at_start: Vec<u32> = self
            .tcp_flows
            .iter()
            .filter(|(_, f)| self.sockets.get::<tcp::Socket>(f.handle).state() == tcp::State::Closed)
            .map(|(id, _)| *id)
            .collect();

        for (id, f) in self.tcp_flows.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(f.handle);
            // A reset from the phone (or the backlog hard cap): abort the
            // stack socket so the app observes a reset; the sweep below
            // removes the flow on the next pass, after a poll has had
            // its chance to put the RST on the wire.
            if f.rst_pending {
                socket.abort();
                work = true;
                continue;
            }
            // Flush phone -> app bytes.
            while let Some(data) = f.pending.front() {
                if !socket.can_send() {
                    break;
                }
                match socket.send_slice(data) {
                    Ok(n) if n == data.len() => {
                        f.pending.pop_front();
                        f.last_progress = StdInstant::now();
                        work = true;
                    }
                    Ok(n) => {
                        if n > 0 {
                            f.last_progress = StdInstant::now();
                        }
                        let rest = data[n..].to_vec();
                        f.pending.pop_front();
                        f.pending.push_front(rest);
                        work = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            // Stall reset: the backlog is pinned at the high-water mark
            // and has made no drain progress for PENDING_STALL_RESET —
            // the app is not reading. Reset the flow (deferred teardown)
            // so the pinned memory is freed and both sides learn the
            // flow is gone, instead of backpressuring it forever.
            if f.pending_len() >= PENDING_HIGH_WATER
                && f.last_progress.elapsed() > PENDING_STALL_RESET
            {
                crate::nxlog(format!(
                    "tcp flow {id}: no drain progress for {:?} with a full backlog — resetting",
                    PENDING_STALL_RESET
                ));
                f.pending.clear();
                f.rst_pending = true;
                continue;
            }
            // The phone's FIN goes to the app only after the last pending
            // byte; the app may still send afterwards (half-close).
            if f.fin_from_phone && f.pending.is_empty() && !f.fin_sent {
                socket.close();
                f.fin_sent = true;
            }
            // App -> phone bytes (only once the phone confirmed the flow).
            // Deliberately NOT gated on may_recv(): it is false in
            // CloseWait with a drained buffer, which would hide the app's
            // FIN forever (recv_slice reports Finished exactly there) and
            // the phone would never see the half-close.
            if f.open {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match socket.recv_slice(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            self.counters.up.fetch_add(n as u64, Ordering::Relaxed);
                            frames.push(Frame::Data { flow: *id, data: buf[..n].to_vec() });
                            work = true;
                        }
                        Err(tcp::RecvError::Finished) => {
                            if !f.fin_to_phone {
                                f.fin_to_phone = true;
                                frames.push(Frame::Close { flow: *id, flags: CLOSE_FIN });
                            }
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        for id in closed_at_start {
            if let Some(f) = self.tcp_flows.remove(&id) {
                self.tcp_by_tuple.remove(&f.tuple);
                self.sockets.remove(f.handle);
                // If the app side died without a FIN (e.g. it aborted),
                // tell the phone to drop its socket too instead of
                // leaving it open until its own timeout.
                if !f.fin_to_phone {
                    frames.push(Frame::Close { flow: id, flags: CLOSE_RST });
                }
                work = true;
            }
        }

        // UDP: app -> phone.
        let mut dead_udp: Vec<u32> = Vec::new();
        for (id, f) in self.udp_flows.iter_mut() {
            let socket = self.sockets.get_mut::<udp::Socket>(f.handle);
            while let Ok((data, _meta)) = socket.recv() {
                crate::nxdebug(format!("udp flow {id}: app packet {} bytes -> phone", data.len()));
                self.counters.up.fetch_add(data.len() as u64, Ordering::Relaxed);
                frames.push(Frame::Data { flow: *id, data: data.to_vec() });
                f.last_seen = StdInstant::now();
                work = true;
            }
            if f.last_seen.elapsed() > Duration::from_secs(60) {
                dead_udp.push(*id);
            }
        }
        for id in dead_udp {
            if let Some(f) = self.udp_flows.remove(&id) {
                self.udp_by_key.remove(&f.key);
                self.sockets.remove(f.handle);
                frames.push(Frame::Close { flow: id, flags: CLOSE_FIN });
                work = true;
            }
        }

        for frame in frames {
            self.queue_frame(&frame);
        }
        work
    }
}

/// Guarantee a probe error names its stage, whatever layer produced
/// it (a link error deep in the wait loop must still surface as e.g.
/// "DNS check failed: …"). Cancellation is not a stage failure and
/// passes through untouched.
fn prefix_stage(label: &str, err: String) -> String {
    if err.starts_with(label) || err == "Connection cancelled" {
        err
    } else {
        format!("{label}: {err}")
    }
}

// ---------------------------------------------------------------------------
// Connect-probe DNS messages
// ---------------------------------------------------------------------------

/// A minimal well-formed DNS query: `example.com`, type A, class IN,
/// recursion desired. Sent through the phone's DNS interception by the
/// DNS probe stage.
fn build_dns_query(txid: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(29);
    q.extend_from_slice(&txid.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    q.push(7);
    q.extend_from_slice(b"example");
    q.push(3);
    q.extend_from_slice(b"com");
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // A
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

/// Is this a valid successful response to our probe query? Checks the
/// header only: matching transaction id, QR set, no error rcode, and
/// at least one answer — enough to prove a resolver at the far end of
/// the tunnel actually resolved the name.
fn valid_dns_response(resp: &[u8], txid: u16) -> bool {
    if resp.len() < 12 {
        return false;
    }
    if u16::from_be_bytes([resp[0], resp[1]]) != txid {
        return false;
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    if flags & 0x8000 == 0 {
        return false; // not a response
    }
    if flags & 0x000F != 0 {
        return false; // rcode: an error, not an answer
    }
    u16::from_be_bytes([resp[6], resp[7]]) >= 1 // ANCOUNT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_is_well_formed() {
        let q = build_dns_query(0x4E58);
        assert_eq!(q.len(), 29);
        assert_eq!(&q[0..2], &[0x4E, 0x58]);
        assert_eq!(&q[12..25], &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
        assert_eq!(&q[25..29], &[0, 1, 0, 1]);
    }

    fn response(txid: u16, flags: u16, answers: u16) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&txid.to_be_bytes());
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&answers.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r.extend_from_slice(&0u16.to_be_bytes());
        r
    }

    #[test]
    fn dns_response_validation() {
        // A normal NOERROR response with one answer.
        assert!(valid_dns_response(&response(0x4E58, 0x8180, 1), 0x4E58));
        // Wrong transaction id.
        assert!(!valid_dns_response(&response(0x1234, 0x8180, 1), 0x4E58));
        // A query, not a response (QR clear).
        assert!(!valid_dns_response(&response(0x4E58, 0x0100, 0), 0x4E58));
        // NXDOMAIN (rcode 3), no answers.
        assert!(!valid_dns_response(&response(0x4E58, 0x8183, 0), 0x4E58));
        // NOERROR but zero answers (NODATA) proves nothing.
        assert!(!valid_dns_response(&response(0x4E58, 0x8180, 0), 0x4E58));
        // Truncated garbage.
        assert!(!valid_dns_response(&[0x4E, 0x58, 0x81], 0x4E58));
    }

    #[test]
    fn stage_prefixing() {
        assert_eq!(
            prefix_stage("DNS check failed", "link error (reset)".to_string()),
            "DNS check failed: link error (reset)"
        );
        // Already named: untouched.
        assert_eq!(
            prefix_stage("DNS check failed", "DNS check failed: no answer".to_string()),
            "DNS check failed: no answer"
        );
        // Cancellation is not a stage failure.
        assert_eq!(
            prefix_stage("DNS check failed", "Connection cancelled".to_string()),
            "Connection cancelled"
        );
    }

    #[test]
    fn link_mtu_is_1400() {
        // The regression guard for the v0.2.1 bug: if this value ever
        // drifts from the adapter's, bulk traffic silently dies again.
        assert_eq!(crate::LINK_MTU, 1400);
    }
}
