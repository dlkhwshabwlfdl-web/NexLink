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
use std::sync::atomic::{AtomicBool, Ordering};
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
        caps.max_transmission_unit = 1500;
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
                    crate::nxlog(format!(
                        "tcp flow {id}: tuple={:?} state={:?} open={}",
                        f.tuple,
                        socket.state(),
                        f.open
                    ));
                }
                for (id, f) in self.udp_flows.iter() {
                    let socket = self.sockets.get::<udp::Socket>(f.handle);
                    crate::nxlog(format!(
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
                crate::nxlog(format!("sniff udp {src}:{} -> {dst}:{}", key.1, key.3));
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
        self.tcp_flows.insert(flow, TcpFlow { handle, tuple, open: false, pending: VecDeque::new(), fin_to_phone: false, fin_from_phone: false, fin_sent: false });
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
                if let Some(f) = self.tcp_flows.remove(&flow) {
                    self.tcp_by_tuple.remove(&f.tuple);
                    let socket = self.sockets.get_mut::<tcp::Socket>(f.handle);
                    socket.abort();
                    self.sockets.remove(f.handle);
                } else if let Some(f) = self.udp_flows.remove(&flow) {
                    self.udp_by_key.remove(&f.key);
                    self.sockets.remove(f.handle);
                }
            }
            Frame::Data { flow, data } => {
                // Cap the phone -> app backlog per flow: a phone that sends
                // faster than the app reads must not grow memory without
                // bound. Past 4 MiB the flow is reset on both sides.
                const MAX_PENDING: usize = 4 * 1024 * 1024;
                let over_cap = match self.tcp_flows.get(&flow) {
                    Some(f) => f.pending.iter().map(|d| d.len()).sum::<usize>() + data.len() > MAX_PENDING,
                    None => false,
                };
                if over_cap {
                    if let Some(f) = self.tcp_flows.remove(&flow) {
                        self.tcp_by_tuple.remove(&f.tuple);
                        let socket = self.sockets.get_mut::<tcp::Socket>(f.handle);
                        socket.abort();
                        self.sockets.remove(f.handle);
                    }
                    self.queue_frame(&Frame::Close { flow, flags: CLOSE_RST });
                    return;
                }
                if let Some(f) = self.tcp_flows.get_mut(&flow) {
                    f.pending.push_back(data);
                } else if let Some(f) = self.udp_flows.get_mut(&flow) {
                    f.last_seen = StdInstant::now();
                    let socket = self.sockets.get_mut::<udp::Socket>(f.handle);
                    let r = socket.send_slice(&data, f.app);
                    crate::nxlog(format!("udp flow {flow}: send_slice {} bytes to {} -> {r:?}", data.len(), f.app));
                }
            }
            Frame::Close { flow, flags } => {
                if flags & CLOSE_RST != 0 {
                    if let Some(f) = self.tcp_flows.remove(&flow) {
                        self.tcp_by_tuple.remove(&f.tuple);
                        let socket = self.sockets.get_mut::<tcp::Socket>(f.handle);
                        socket.abort();
                        self.sockets.remove(f.handle);
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
        let mut dead_tcp: Vec<u32> = Vec::new();
        let mut frames: Vec<Frame> = Vec::new();

        for (id, f) in self.tcp_flows.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(f.handle);
            // Flush phone -> app bytes.
            while let Some(data) = f.pending.front() {
                if !socket.can_send() {
                    break;
                }
                match socket.send_slice(data) {
                    Ok(n) if n == data.len() => {
                        f.pending.pop_front();
                        work = true;
                    }
                    Ok(n) => {
                        let rest = data[n..].to_vec();
                        f.pending.pop_front();
                        f.pending.push_front(rest);
                        work = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            // The phone's FIN goes to the app only after the last pending
            // byte; the app may still send afterwards (half-close).
            if f.fin_from_phone && f.pending.is_empty() && !f.fin_sent {
                socket.close();
                f.fin_sent = true;
            }
            // App -> phone bytes (only once the phone confirmed the flow).
            if f.open && socket.may_recv() {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match socket.recv_slice(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
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
            if socket.state() == tcp::State::Closed {
                dead_tcp.push(*id);
            }
        }
        for id in dead_tcp {
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
                crate::nxlog(format!("udp flow {id}: app packet {} bytes -> phone", data.len()));
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
