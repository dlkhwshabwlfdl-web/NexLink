//! NexLink STRICT end-to-end battery — adversarial checks beyond the
//! default suite (`test-e2e.sh`). Same shape as `e2e` (virtual PC app →
//! real engine → real simphone → real local servers) plus in-process
//! NXLP phone doubles for the cases a well-behaved simphone cannot
//! produce (a peer that goes silent, a peer that counts flow closes).
//!
//! Checks (S-numbers are referenced by the strict-test report):
//!   S1  Hostile transport: handshake, probes and a 1 MiB transfer run
//!       through a byte-mangling TCP relay (1–7 byte dribbles, partial
//!       reads/writes) — the same shape as the adb-forward hop.
//!   S2  Bulk stress: 10 MiB down byte-identical (+hash), traffic
//!       counters at zero after probes and ≥ the bulk sizes after.
//!   S2b Bulk up: a 1 MiB POST body echoed back byte-identical.
//!   S3  Eight concurrent TCP flows of mixed sizes, each verified
//!       against its own pattern (no cross-flow corruption, no stall).
//!   S4  MTU edges: echoed payloads of exactly 1399 / 1400 / 1401
//!       bytes arrive intact; no engine packet ever exceeds 1400.
//!   S5  DNS: several names resolved via interception; an NXDOMAIN
//!       answer passes through with rcode 3 intact.
//!   S6  DNS with a dead upstream resolver: the query gets no answer
//!       (clean timeout at the app layer) and the engine keeps working.
//!   S7  Probe NEGATIVE tests: (a) phone never answers DNS →
//!       "DNS check failed"; (b) DNS fine, TCP refused →
//!       "Traffic check failed"; (c) link killed before the probes →
//!       a named stage error, promptly. No indefinite hangs.
//!   S8  Flow churn: 500 rapid open/close cycles, all succeed.
//!   S9  Destination RST mid-transfer: the app observes a reset (not a
//!       graceful end), the engine survives, the next flow works.
//!   S10 Half-close: the app FINs after its request and still receives
//!       the full response afterwards.
//!   S11 Link severed mid-transfer (simphone killed): the engine
//!       reports the dead link promptly; a fresh tunnel then works.
//!   S12 Silent peer: the phone sends data, then goes completely
//!       silent with the socket open — the engine must declare the
//!       link dead at its documented 60 s no-frames window.
//!   S13 UDP over the link: datagrams cross both ways intact, per-flow
//!       separation across simultaneous associations (NXLP double —
//!       this sandbox blocks real UDP entirely, see S14).
//!   S14 UDP via simphone to a real UDP echo server. ENVIRONMENT
//!       GATED: this VM's sandbox returns EPERM for every UDP send,
//!       even on loopback, so the check SKIPs (loudly) when a direct
//!       loopback probe fails. On a normal machine it runs for real.
//!   S15 Idle UDP associations are reaped: 20 associations opened, the
//!       phone double must receive a Close for every one of them at
//!       the engine's 60 s idle expiry, and the engine stays alive.
//!
//! Exit code 0 = PASS (skips reported, never counted as passes),
//! 1 = FAIL.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken as PhyRxToken, TxToken as PhyTxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use nxcore::engine::{client_handshake, Engine, TrafficCounters};
use nxcore::proto::*;

// ---------------------------------------------------------------------------
// Deterministic payload patterns + a small hash for reporting.
// ---------------------------------------------------------------------------

/// Position- and seed-dependent bytes: truncation, reordering, and
/// cross-flow mix-ups all change the comparison result.
fn pattern(seed: u64, len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    for i in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push(((x >> 32) as u8) ^ (i as u8));
    }
    v
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn fail(msg: &str) -> ! {
    eprintln!("STRICT FAIL: {msg}");
    std::process::exit(1);
}

fn check(cond: bool, msg: &str) {
    if !cond {
        fail(msg);
    }
}

// ---------------------------------------------------------------------------
// Channel device for the virtual app's stack (same as the default e2e,
// plus tracking of the largest packet the engine ever emits).
// ---------------------------------------------------------------------------

struct ChanDevice {
    rx: Receiver<Vec<u8>>,
    tx: Sender<Vec<u8>>,
    max_rx: Arc<AtomicU64>,
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
        match self.rx.try_recv() {
            Ok(pkt) => {
                self.max_rx.fetch_max(pkt.len() as u64, Ordering::Relaxed);
                Some((RxTok(pkt), TxTok(self.tx.clone())))
            }
            Err(_) => None,
        }
    }

    fn transmit(&mut self, _ts: Instant) -> Option<TxTok> {
        Some(TxTok(self.tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = nxcore::LINK_MTU;
        caps
    }
}

// ---------------------------------------------------------------------------
// Local servers: HTTP on 127.0.0.1:18081, fake DNS on 127.0.0.1:15363,
// UDP echo on 127.0.0.1:15364 (used only where the sandbox allows UDP).
// ---------------------------------------------------------------------------

fn query_param(path: &str, key: &str) -> Option<u64> {
    let query = path.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return v.parse().ok();
        }
    }
    None
}

fn read_request_head(s: &mut TcpStream) -> Option<(String, usize)> {
    let mut buf = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") && buf.len() < 16 * 1024 {
        match s.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => buf.push(byte[0]),
            Err(_) => return None,
        }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let first = head.lines().next().unwrap_or("").to_string();
    let mut content_length = 0usize;
    for line in head.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    Some((first, content_length))
}

/// Arm `s` so that closing it sends RST (SO_LINGER, zero timeout).
/// Non-unix fallback is a deliberate no-op: the strict battery targets
/// the Linux VM, and on another platform /rst degrades to a plain FIN —
/// S9 then fails loudly instead of passing on a reset that never
/// happened.
#[cfg(not(unix))]
fn force_rst(_s: &TcpStream) {}

#[cfg(unix)]
fn force_rst(s: &TcpStream) {
    use std::os::unix::io::AsRawFd;
    #[repr(C)]
    struct Linger {
        onoff: i32,
        linger: i32,
    }
    extern "C" {
        fn setsockopt(fd: i32, level: i32, name: i32, val: *const Linger, len: u32) -> i32;
    }
    let l = Linger { onoff: 1, linger: 0 };
    unsafe {
        let _ = setsockopt(s.as_raw_fd(), 1, 13, &l, 8);
    }
}

fn http_respond(s: &mut TcpStream, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
}

fn handle_http_conn(mut s: TcpStream) {
    let _ = s.set_nodelay(true);
    let Some((first, content_length)) = read_request_head(&mut s) else { return };
    let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
    if path.starts_with("/sized") {
        let len = query_param(&path, "len").unwrap_or(0) as usize;
        let seed = query_param(&path, "seed").unwrap_or(0);
        http_respond(&mut s, &pattern(seed, len));
    } else if path.starts_with("/echo") {
        let mut body = vec![0u8; content_length];
        if s.read_exact(&mut body).is_err() {
            return;
        }
        http_respond(&mut s, &body);
    } else if path.starts_with("/afterfin") {
        // Read the request body until the client's FIN (EOF), THEN
        // answer — the half-close scenario: the client has closed its
        // send side but must still receive this response.
        let mut sink = Vec::new();
        let _ = s.read_to_end(&mut sink);
        let len = query_param(&path, "len").unwrap_or(0) as usize;
        let seed = query_param(&path, "seed").unwrap_or(0);
        http_respond(&mut s, &pattern(seed, len));
    } else if path.starts_with("/rst") {
        // Claim a large body, deliver a slice of it, pause so the
        // slice is read, then RST: SO_LINGER with a zero timeout makes
        // the close() below send RST instead of FIN. (std's
        // TcpStream::set_linger is unstable, hence the direct call.)
        let head = "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n";
        let _ = s.write_all(head.as_bytes());
        let _ = s.write_all(&pattern(3, 8192));
        let _ = s.flush();
        std::thread::sleep(Duration::from_millis(150));
        force_rst(&s);
        // Dropping the stream now sends RST (zero linger).
    } else {
        http_respond(&mut s, b"nexlink-strict-ok");
    }
}

fn start_http_server() {
    let listener = TcpListener::bind("127.0.0.1:18081").expect("http bind");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(s) = stream {
                std::thread::spawn(move || handle_http_conn(s));
            }
        }
    });
}

/// Build a DNS response for `query`: a normal A answer (203.0.113.99),
/// or NXDOMAIN (rcode 3, no answers) for names under `.nx.test`.
fn dns_response(query: &[u8]) -> Vec<u8> {
    // Parse the qname.
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();
    while pos < query.len() && query[pos] != 0 {
        let n = query[pos] as usize;
        pos += 1;
        labels.push(String::from_utf8_lossy(&query[pos..pos + n]).to_string());
        pos += n;
    }
    let qend = pos + 5; // root byte + qtype + qclass
    let nxdomain = labels.last().map(|l| l == "test").unwrap_or(false)
        && labels.iter().any(|l| l == "nx");
    let mut out = Vec::new();
    out.extend_from_slice(&query[0..2]); // txid
    let flags: u16 = if nxdomain { 0x8183 } else { 0x8180 };
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qd
    out.extend_from_slice(&if nxdomain { 0u16 } else { 1u16 }.to_be_bytes()); // an
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..qend]); // question
    if !nxdomain {
        out.extend_from_slice(&0xC00Cu16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&[203, 0, 113, 99]);
    }
    out
}

fn start_fake_dns() {
    // UDP (normal transport; unreachable inside this sandbox, harmless).
    if let Ok(sock) = UdpSocket::bind("127.0.0.1:15363") {
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        let resp = dns_response(&buf[..n]);
                        let _ = sock.send_to(&resp, addr);
                    }
                    Err(_) => return,
                }
            }
        });
    }
    // TCP (DNS-over-TCP — the transport simphone falls back to here).
    let listener = TcpListener::bind("127.0.0.1:15363").expect("dns tcp bind");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || loop {
                let mut len_buf = [0u8; 2];
                if s.read_exact(&mut len_buf).is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut query = vec![0u8; len];
                if s.read_exact(&mut query).is_err() {
                    return;
                }
                let resp = dns_response(&query);
                if s.write_all(&(resp.len() as u16).to_be_bytes()).is_err() {
                    return;
                }
                if s.write_all(&resp).is_err() {
                    return;
                }
            });
        }
    });
}

fn start_udp_echo() {
    if let Ok(sock) = UdpSocket::bind("127.0.0.1:15364") {
        std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        let _ = sock.send_to(&buf[..n], addr);
                    }
                    Err(_) => return,
                }
            }
        });
    }
}

/// Can this machine send a UDP datagram on loopback at all? (The Muse
/// VM sandbox answers EPERM; S14 uses this to SKIP honestly.)
fn udp_loopback_works() -> bool {
    let Ok(server) = UdpSocket::bind("127.0.0.1:0") else { return false };
    let Ok(addr) = server.local_addr() else { return false };
    let _ = server.set_read_timeout(Some(Duration::from_millis(500)));
    let Ok(client) = UdpSocket::bind("127.0.0.1:0") else { return false };
    if client.send_to(b"probe", addr).is_err() {
        return false;
    }
    let mut buf = [0u8; 16];
    server.recv(&mut buf).is_ok()
}

// ---------------------------------------------------------------------------
// simphone subprocess
// ---------------------------------------------------------------------------

fn simphone_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let dir = exe.parent().unwrap();
    for cand in [dir.join("simphone"), dir.join("../simphone"), dir.join("../../simphone")] {
        if cand.exists() {
            return cand;
        }
    }
    panic!("simphone binary not found next to the e2e binary — build the workspace first");
}

/// Spawn simphone with the standard maps for this suite plus any extra
/// arguments the caller needs (custom --dns, custom --map, ...).
fn start_simphone(listen: &str, extra: &[&str]) -> Child {
    let mut cmd = Command::new(simphone_path());
    cmd.arg("--listen").arg(listen)
        .arg("--map").arg("203.0.113.7:18081=127.0.0.1:18081")
        .arg("--map").arg("1.1.1.1:443=127.0.0.1:18081")
        .arg("--map").arg("203.0.113.8:5353=127.0.0.1:15364")
        .arg("--dns").arg("127.0.0.1:15363")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    for a in extra {
        cmd.arg(a);
    }
    let child = cmd.spawn().expect("spawn simphone");
    std::thread::sleep(Duration::from_millis(500));
    child
}

// ---------------------------------------------------------------------------
// Engine thread + the virtual-app harness.
// ---------------------------------------------------------------------------

struct EngineHandle {
    probe_rx: Receiver<Result<(), String>>,
    run_rx: Receiver<std::io::Result<()>>,
}

/// Spawn the engine on its own thread over the given (already
/// handshaken) link. When `probes` is set, the thread runs the
/// connect probes first (result on `probe_rx`) and only starts the
/// main loop if they pass.
fn spawn_engine(
    link: TcpStream,
    probes: bool,
    stop: Arc<AtomicBool>,
    counters: TrafficCounters,
) -> (Sender<Vec<u8>>, Receiver<Vec<u8>>, EngineHandle) {
    let (app_out_tx, engine_in_rx) = channel::<Vec<u8>>();
    let (engine_out_tx, app_in_rx) = channel::<Vec<u8>>();
    let (probe_tx, probe_rx) = channel::<Result<(), String>>();
    let (run_tx, run_rx) = channel::<std::io::Result<()>>();
    std::thread::spawn(move || {
        let mut engine = Engine::new(
            engine_in_rx,
            engine_out_tx,
            link,
            Ipv4Address::new(10, 77, 0, 1),
            counters,
        )
        .expect("engine init");
        let probe = if probes {
            engine.run_probes(&stop, &mut |_| {})
        } else {
            Ok(())
        };
        let _ = probe_tx.send(probe.clone());
        let res = if probe.is_ok() {
            engine.run(stop)
        } else {
            Ok(())
        };
        let _ = run_tx.send(res);
    });
    (app_out_tx, app_in_rx, EngineHandle { probe_rx, run_rx })
}

struct Harness {
    dev: ChanDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    stop: Arc<AtomicBool>,
    engine: EngineHandle,
    counters: TrafficCounters,
    max_rx: Arc<AtomicU64>,
}

impl Harness {
    /// Connect a link to `link_addr`, handshake, and start the engine
    /// plus the virtual app stack (10.77.0.2).
    fn start(link_addr: &str, probes: bool) -> Harness {
        let mut link = TcpStream::connect(link_addr)
            .unwrap_or_else(|e| fail(&format!("link connect {link_addr}: {e}")));
        let hello = client_handshake(&mut link, "e2e-strict")
            .unwrap_or_else(|e| fail(&format!("handshake: {e}")));
        if !hello.armed {
            fail("phone reported armed = false");
        }
        let counters = TrafficCounters::new();
        let stop = Arc::new(AtomicBool::new(false));
        let (app_out_tx, app_in_rx, engine) =
            spawn_engine(link, probes, stop.clone(), counters.clone());
        let max_rx = Arc::new(AtomicU64::new(0));
        let mut dev = ChanDevice { rx: app_in_rx, tx: app_out_tx, max_rx: max_rx.clone() };
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, Instant::now());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 2)), 24));
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 77, 0, 1))
            .unwrap();
        Harness {
            dev,
            iface,
            sockets: SocketSet::new(vec![]),
            stop,
            engine,
            counters,
            max_rx,
        }
    }

    fn poll(&mut self) {
        self.iface.poll(Instant::now(), &mut self.dev, &mut self.sockets);
        std::thread::sleep(Duration::from_millis(1));
    }

    fn await_probes(&self, timeout: Duration) -> Result<(), String> {
        match self.engine.probe_rx.recv_timeout(timeout) {
            Ok(r) => r,
            Err(_) => Err("probes did not finish in time".to_string()),
        }
    }

    /// Stop the engine and return how its run ended.
    fn shutdown(self) -> std::io::Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        match self.engine.run_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "engine did not stop")),
        }
    }
}

// ---------------------------------------------------------------------------
// TCP exchange helper: one full request/response over the tunnel.
// ---------------------------------------------------------------------------

struct TcpOutcome {
    /// The full response stream (HTTP headers included).
    received: Vec<u8>,
    /// The peer's FIN was observed (graceful end of stream).
    graceful: bool,
    /// The socket reached Closed without a graceful FIN.
    reset: bool,
}

fn strip_http(received: &[u8]) -> &[u8] {
    match received.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(p) => &received[p + 4..],
        None => fail("response has no HTTP header terminator"),
    }
}

/// Drive one TCP flow: connect to (dst, dport) from local port `local`,
/// send `request` in full, optionally half-close after sending, then
/// read until FIN / reset / deadline.
fn tcp_exchange(
    h: &mut Harness,
    dst: Ipv4Address,
    dport: u16,
    local: u16,
    request: &[u8],
    half_close: bool,
    deadline: Duration,
) -> Result<TcpOutcome, String> {
    let mut sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 256 * 1024]),
        tcp::SocketBuffer::new(vec![0; 64 * 1024]),
    );
    sock.set_nagle_enabled(false);
    sock.connect(h.iface.context(), IpEndpoint::new(IpAddress::Ipv4(dst), dport), local)
        .map_err(|e| format!("app connect: {e:?}"))?;
    let handle = h.sockets.add(sock);
    let end = StdInstant::now() + deadline;
    let mut sent = 0usize;
    let mut did_half_close = false;
    let mut out = TcpOutcome { received: Vec::new(), graceful: false, reset: false };
    while StdInstant::now() < end {
        h.poll();
        let socket = h.sockets.get_mut::<tcp::Socket>(handle);
        if sent < request.len() && socket.state() == tcp::State::Established && socket.can_send() {
            match socket.send_slice(&request[sent..]) {
                Ok(n) => sent += n,
                Err(e) => return Err(format!("app send: {e:?}")),
            }
        }
        if sent == request.len() && half_close && !did_half_close {
            socket.close();
            did_half_close = true;
        }
        // NOTE: recv_slice is called unconditionally — gating on
        // may_recv() would hide the peer's FIN forever (in CloseWait
        // with a drained buffer may_recv() is false, yet recv_slice
        // is exactly what returns Err(Finished) there).
        {
            let mut buf = [0u8; 32768];
            match socket.recv_slice(&mut buf) {
                Ok(0) => {}
                Ok(n) => out.received.extend_from_slice(&buf[..n]),
                Err(tcp::RecvError::Finished) => {
                    out.graceful = true;
                    break;
                }
                Err(_) => {}
            }
        }
        if socket.state() == tcp::State::Closed {
            out.reset = !out.graceful;
            break;
        }
    }
    // Clean up the socket (full close handshake when possible).
    {
        let socket = h.sockets.get_mut::<tcp::Socket>(handle);
        if socket.state() != tcp::State::Closed {
            socket.close();
        }
    }
    let cleanup_end = StdInstant::now() + Duration::from_secs(2);
    while StdInstant::now() < cleanup_end {
        h.poll();
        if h.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Closed {
            break;
        }
    }
    h.sockets.remove(handle);
    if !out.graceful && !out.reset {
        return Err(format!(
            "exchange timed out after {deadline:?} ({} bytes received)",
            out.received.len()
        ));
    }
    Ok(out)
}

fn get(h: &mut Harness, path: &str, local: u16, deadline: Duration) -> Result<TcpOutcome, String> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: 203.0.113.7\r\nConnection: close\r\n\r\n");
    tcp_exchange(h, Ipv4Address::new(203, 0, 113, 7), 18081, local, req.as_bytes(), false, deadline)
}

// ---------------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------------

fn dns_query(txid: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&txid.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    q.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q
}

/// One UDP socket on the app stack, bound to `local`, used for a batch
/// of DNS queries to (server, 53). Returns txid → (rcode, ancount,
/// answer's last 4 bytes) for every response seen within `wait`.
fn dns_batch(
    h: &mut Harness,
    local: u16,
    server: Ipv4Address,
    queries: &[(u16, &str)],
    wait: Duration,
) -> std::collections::HashMap<u16, (u16, u16, Vec<u8>)> {
    let mut sock = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]),
    );
    sock.bind(local).unwrap_or_else(|e| fail(&format!("dns udp bind: {e:?}")));
    let handle = h.sockets.add(sock);
    let end = StdInstant::now() + wait;
    let mut sent = false;
    let mut answers = std::collections::HashMap::new();
    while StdInstant::now() < end {
        h.poll();
        let socket = h.sockets.get_mut::<udp::Socket>(handle);
        if !sent {
            for (txid, name) in queries {
                let q = dns_query(*txid, name);
                socket
                    .send_slice(&q, IpEndpoint::new(IpAddress::Ipv4(server), 53))
                    .unwrap_or_else(|e| fail(&format!("dns send: {e:?}")));
            }
            sent = true;
        }
        while let Ok((data, _meta)) = socket.recv() {
            if data.len() >= 12 {
                let txid = u16::from_be_bytes([data[0], data[1]]);
                let flags = u16::from_be_bytes([data[2], data[3]]);
                let an = u16::from_be_bytes([data[6], data[7]]);
                let tail = data[data.len().saturating_sub(4)..].to_vec();
                answers.insert(txid, (flags & 0x000F, an, tail));
            }
        }
        if answers.len() == queries.len() {
            break;
        }
    }
    h.sockets.remove(handle);
    answers
}

// ---------------------------------------------------------------------------
// S1: hostile TCP relay — arbitrary segmentation in both directions,
// the same stream shape the adb-forward hop presents.
// ---------------------------------------------------------------------------

fn hostile_pump(mut rd: TcpStream, mut wr: TcpStream, cycle: &'static [usize]) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut i = 0usize;
    loop {
        let want = cycle[i % cycle.len()].min(buf.len());
        i += 1;
        match rd.read(&mut buf[..want]) {
            Ok(0) => {
                let _ = wr.shutdown(std::net::Shutdown::Both);
                return;
            }
            Ok(n) => {
                if wr.write_all(&buf[..n]).is_err() {
                    return;
                }
                let _ = wr.flush();
            }
            Err(_) => return,
        }
    }
}

fn start_hostile_relay(listen: &str, target: &str) {
    let listener = TcpListener::bind(listen).expect("relay bind");
    let target = target.to_string();
    std::thread::spawn(move || {
        let Ok((client, _)) = listener.accept() else { return };
        let Ok(server) = TcpStream::connect(&target) else { return };
        let _ = client.set_nodelay(true);
        let _ = server.set_nodelay(true);
        let c2 = client.try_clone().unwrap();
        let s2 = server.try_clone().unwrap();
        std::thread::spawn(move || hostile_pump(client, s2, &[1, 7, 3, 1024, 1, 1, 65536, 13, 4096, 2]));
        std::thread::spawn(move || hostile_pump(server, c2, &[5, 1, 8192, 3, 32768, 1, 64, 11]));
    });
}

// ---------------------------------------------------------------------------
// In-process NXLP phone doubles (raw framed streams via nxcore::proto).
// ---------------------------------------------------------------------------

fn send_frame_locked(link: &Mutex<TcpStream>, frame: &Frame) {
    let mut buf = Vec::with_capacity(1024);
    frame.encode(&mut buf);
    let mut s = link.lock().unwrap();
    let _ = s.write_all(&buf);
}

/// Read frames until EOF, dispatching each to `on_frame`. Returns when
/// the stream ends or errors.
fn double_read_loop(stream: TcpStream, link: Arc<Mutex<TcpStream>>, on_frame: &mut dyn FnMut(&Frame, &Arc<Mutex<TcpStream>>)) {
    let mut reader_stream = stream;
    let mut fr = FrameReader::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match reader_stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => {
                fr.feed(&chunk[..n]);
                while let Ok(Some(frame)) = fr.next_frame() {
                    on_frame(&frame, &link);
                }
            }
            Err(_) => return,
        }
    }
}

// ---------------------------------------------------------------------------
// S12 (thread): the silent peer. The double answers the handshake,
// opens the flow, sends 32 KiB — then goes completely silent with the
// socket held open. The engine must declare the link dead inside its
// documented 60 s no-frames window, having delivered the data first.
// ---------------------------------------------------------------------------

fn zombie_test() -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:47795").map_err(|e| e.to_string())?;
    // The zombie double.
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else { return };
        let link = Arc::new(Mutex::new(stream.try_clone().unwrap()));
        let payload = pattern(77, 32768);
        double_read_loop(stream, link, &mut |frame, link| {
            match frame {
                Frame::Hello { .. } => {
                    send_frame_locked(link, &Frame::HelloAck { armed: true, name: "zombie".into() });
                }
                Frame::Open { flow, .. } => {
                    send_frame_locked(link, &Frame::OpenOk { flow: *flow });
                    for chunk in payload.chunks(16384) {
                        send_frame_locked(link, &Frame::Data { flow: *flow, data: chunk.to_vec() });
                    }
                }
                // Ping deliberately unanswered: total silence is the
                // scenario under test. Data frames are drained and
                // dropped so the engine's writes never block.
                _ => {}
            }
        });
    });
    std::thread::sleep(Duration::from_millis(300));

    let mut link = TcpStream::connect("127.0.0.1:47795").map_err(|e| e.to_string())?;
    client_handshake(&mut link, "e2e-strict-zombie").map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let engine_start = StdInstant::now();
    let (app_out_tx, app_in_rx, engine) =
        spawn_engine(link, false, stop.clone(), TrafficCounters::new());
    let max_rx = Arc::new(AtomicU64::new(0));
    let mut dev = ChanDevice { rx: app_in_rx, tx: app_out_tx, max_rx };
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, Instant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 2)), 24));
    });
    iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 77, 0, 1)).unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let mut sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 128 * 1024]),
        tcp::SocketBuffer::new(vec![0; 16 * 1024]),
    );
    sock.connect(
        iface.context(),
        IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 7)), 18081),
        49001,
    )
    .map_err(|e| format!("zombie app connect: {e:?}"))?;
    let handle = sockets.add(sock);
    // Collect the zombie's 32 KiB, then wait for the engine to die.
    let mut received: Vec<u8> = Vec::new();
    let data_deadline = StdInstant::now() + Duration::from_secs(15);
    while StdInstant::now() < data_deadline && received.len() < 32768 {
        iface.poll(Instant::now(), &mut dev, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        let mut buf = [0u8; 16384];
        if let Ok(n) = socket.recv_slice(&mut buf) {
            received.extend_from_slice(&buf[..n]);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if received != pattern(77, 32768) {
        return Err(format!(
            "zombie data: got {} bytes before the silence, expected 32768 intact",
            received.len()
        ));
    }
    match engine.run_rx.recv_timeout(Duration::from_secs(100)) {
        Ok(Err(e)) => {
            let elapsed = engine_start.elapsed();
            if !e.to_string().contains("link is dead") {
                return Err(format!("engine died with an unexpected error: {e}"));
            }
            if elapsed < Duration::from_secs(50) || elapsed > Duration::from_secs(90) {
                return Err(format!(
                    "link declared dead after {elapsed:?}, outside the documented ~60 s window"
                ));
            }
            Ok(format!(
                "peer went silent after 32 KiB; engine delivered the data, then declared the link dead at {elapsed:.0?} with \"{e}\""
            ))
        }
        Ok(Ok(())) => Err("engine exited cleanly against a silent peer — the dead link was never detected".to_string()),
        Err(_) => Err("engine still running 100 s after the peer went silent — dead link not detected".to_string()),
    }
}

// ---------------------------------------------------------------------------
// S15 (thread): idle UDP association cleanup. The counting double
// records every UDP Open and every Close; it PONGs so the link itself
// stays alive past the 60 s idle window. The engine must reap all 20
// idle associations (Close FIN on the wire) and keep running.
// ---------------------------------------------------------------------------

fn udp_cleanup_test() -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:47796").map_err(|e| e.to_string())?;
    let opened = Arc::new(Mutex::new(Vec::<u32>::new()));
    let closed = Arc::new(Mutex::new(Vec::<u32>::new()));
    {
        let opened = opened.clone();
        let closed = closed.clone();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else { return };
            let link = Arc::new(Mutex::new(stream.try_clone().unwrap()));
            double_read_loop(stream, link, &mut |frame, link| {
                match frame {
                    Frame::Hello { .. } => {
                        send_frame_locked(link, &Frame::HelloAck { armed: true, name: "counter".into() });
                    }
                    Frame::Open { flow, proto, .. } => {
                        if *proto == PROTO_UDP {
                            opened.lock().unwrap().push(*flow);
                        }
                        send_frame_locked(link, &Frame::OpenOk { flow: *flow });
                    }
                    Frame::Close { flow, .. } => {
                        closed.lock().unwrap().push(*flow);
                    }
                    Frame::Ping => send_frame_locked(link, &Frame::Pong),
                    _ => {}
                }
            });
        });
    }
    std::thread::sleep(Duration::from_millis(300));

    let mut link = TcpStream::connect("127.0.0.1:47796").map_err(|e| e.to_string())?;
    client_handshake(&mut link, "e2e-strict-cleanup").map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let (app_out_tx, app_in_rx, engine) =
        spawn_engine(link, false, stop.clone(), TrafficCounters::new());
    let max_rx = Arc::new(AtomicU64::new(0));
    let mut dev = ChanDevice { rx: app_in_rx, tx: app_out_tx, max_rx };
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, Instant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 2)), 24));
    });
    iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 77, 0, 1)).unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let mut udp_sock = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 8192]),
    );
    udp_sock.bind(54000).map_err(|e| format!("cleanup udp bind: {e:?}"))?;
    let handle = sockets.add(udp_sock);

    let poll = |iface: &mut Interface, dev: &mut ChanDevice, sockets: &mut SocketSet<'_>| {
        iface.poll(Instant::now(), dev, sockets);
        std::thread::sleep(Duration::from_millis(1));
    };

    // Open 20 associations: one datagram each, distinct destinations.
    let t_open = StdInstant::now();
    for i in 0..20u16 {
        let socket = sockets.get_mut::<udp::Socket>(handle);
        socket
            .send_slice(
                &[0xAB, (i >> 8) as u8, (i & 0xFF) as u8],
                IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 9)), 6000 + i),
            )
            .map_err(|e| format!("cleanup send {i}: {e:?}"))?;
        for _ in 0..10 {
            poll(&mut iface, &mut dev, &mut sockets);
        }
    }
    // Wait for the double to confirm all 20 opens.
    let open_deadline = StdInstant::now() + Duration::from_secs(15);
    while opened.lock().unwrap().len() < 20 && StdInstant::now() < open_deadline {
        poll(&mut iface, &mut dev, &mut sockets);
    }
    let n_opened = opened.lock().unwrap().len();
    if n_opened != 20 {
        return Err(format!("counting double saw {n_opened}/20 UDP opens"));
    }
    // Idle: the engine must reap every association at ~60 s.
    let close_deadline = StdInstant::now() + Duration::from_secs(110);
    while closed.lock().unwrap().len() < 20 && StdInstant::now() < close_deadline {
        poll(&mut iface, &mut dev, &mut sockets);
    }
    let n_closed = closed.lock().unwrap().len();
    let reap_elapsed = t_open.elapsed();
    if n_closed != 20 {
        return Err(format!(
            "only {n_closed}/20 idle UDP associations were reaped within 110 s"
        ));
    }
    if reap_elapsed < Duration::from_secs(50) {
        return Err(format!(
            "associations reaped after only {reap_elapsed:?} — that is teardown, not idle expiry"
        ));
    }
    // The engine must still be alive (the double's PONGs kept the link
    // fresh): stop it cleanly and expect Ok.
    stop.store(true, Ordering::Relaxed);
    match engine.run_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => Ok(format!(
            "20/20 idle UDP associations reaped by Close at {reap_elapsed:.0?} (60 s idle window); engine stayed alive and stopped cleanly"
        )),
        Ok(Err(e)) => Err(format!("engine died during the idle wait: {e}")),
        Err(_) => Err("engine did not stop when asked".to_string()),
    }
}

// ---------------------------------------------------------------------------
// S13: UDP through the engine to an NXLP double that echoes at the
// frame level (the engine↔phone leg is TCP; the phone↔server UDP leg
// cannot run in this sandbox — see S14).
// ---------------------------------------------------------------------------

fn udp_double_test() -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:47797").map_err(|e| e.to_string())?;
    let opens = Arc::new(Mutex::new(Vec::<(u32, u16)>::new())); // (flow, dst port)
    let payloads = Arc::new(Mutex::new(Vec::<(u32, Vec<u8>)>::new()));
    {
        let opens = opens.clone();
        let payloads = payloads.clone();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else { return };
            let link = Arc::new(Mutex::new(stream.try_clone().unwrap()));
            double_read_loop(stream, link, &mut |frame, link| {
                match frame {
                    Frame::Hello { .. } => {
                        send_frame_locked(link, &Frame::HelloAck { armed: true, name: "udpecho".into() });
                    }
                    Frame::Open { flow, proto, port, .. } => {
                        if *proto == PROTO_UDP {
                            opens.lock().unwrap().push((*flow, *port));
                            send_frame_locked(link, &Frame::OpenOk { flow: *flow });
                        } else {
                            send_frame_locked(link, &Frame::OpenErr { flow: *flow, code: ERR_CONNECT_FAILED });
                        }
                    }
                    Frame::Data { flow, data } => {
                        payloads.lock().unwrap().push((*flow, data.clone()));
                        send_frame_locked(link, &Frame::Data { flow: *flow, data: data.clone() });
                    }
                    Frame::Ping => send_frame_locked(link, &Frame::Pong),
                    _ => {}
                }
            });
        });
    }
    std::thread::sleep(Duration::from_millis(300));

    let mut h = Harness::start("127.0.0.1:47797", false);
    let mut sock = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]),
    );
    sock.bind(54545).map_err(|e| format!("udp double bind: {e:?}"))?;
    let handle = h.sockets.add(sock);
    let cases: [(u16, Vec<u8>); 3] = [
        (7001, pattern(31, 300)),
        (7002, pattern(32, 1372)),
        (7003, pattern(33, 64)),
    ];
    {
        let socket = h.sockets.get_mut::<udp::Socket>(handle);
        for (port, payload) in &cases {
            socket
                .send_slice(
                    payload,
                    IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 10)), *port),
                )
                .map_err(|e| format!("udp double send: {e:?}"))?;
        }
    }
    let mut got: Vec<Vec<u8>> = Vec::new();
    let end = StdInstant::now() + Duration::from_secs(15);
    while StdInstant::now() < end && got.len() < 3 {
        h.poll();
        let socket = h.sockets.get_mut::<udp::Socket>(handle);
        while let Ok((data, _meta)) = socket.recv() {
            got.push(data.to_vec());
        }
    }
    h.sockets.remove(handle);
    let mut expected: Vec<Vec<u8>> = cases.iter().map(|(_, p)| p.clone()).collect();
    let mut got_sorted = got.clone();
    got_sorted.sort();
    expected.sort();
    if got_sorted != expected {
        return Err(format!(
            "udp double: app received {} datagrams, expected the 3 sent payloads back intact",
            got.len()
        ));
    }
    let opens = opens.lock().unwrap();
    let mut open_ports: Vec<u16> = opens.iter().map(|(_, p)| *p).collect();
    open_ports.sort();
    if open_ports != vec![7001, 7002, 7003] {
        return Err(format!("udp double: phone saw opens for ports {open_ports:?}"));
    }
    let flow_ids: std::collections::HashSet<u32> = opens.iter().map(|(f, _)| *f).collect();
    if flow_ids.len() != 3 {
        return Err("udp double: the 3 associations did not get distinct flow ids".to_string());
    }
    let recorded = payloads.lock().unwrap();
    if recorded.len() != 3 {
        return Err(format!("udp double: phone recorded {} payloads, expected 3", recorded.len()));
    }
    for (flow, data) in recorded.iter() {
        let port = opens.iter().find(|(f, _)| f == flow).map(|(_, p)| *p).unwrap_or(0);
        let want = &cases.iter().find(|(p, _)| *p == port).unwrap().1;
        if data != want {
            return Err(format!("udp double: payload for port {port} corrupted at the phone"));
        }
    }
    drop(recorded);
    drop(opens);
    h.shutdown().map_err(|e| format!("udp double engine shutdown: {e}"))?;
    Ok("3 simultaneous UDP associations: datagrams intact in both directions, per-flow separation verified at the phone".to_string())
}

// ---------------------------------------------------------------------------
// S7 helper: run only the connect probes against a link.
// ---------------------------------------------------------------------------

fn probe_once(link_addr: &str, kill_after_handshake: Option<&mut Child>) -> (Result<(), String>, Duration) {
    let mut link = TcpStream::connect(link_addr)
        .unwrap_or_else(|e| fail(&format!("probe link connect {link_addr}: {e}")));
    client_handshake(&mut link, "e2e-strict-probe")
        .unwrap_or_else(|e| fail(&format!("probe handshake: {e}")));
    if let Some(child) = kill_after_handshake {
        let _ = child.kill();
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(200));
    }
    let (_dev_in, dev_rx) = channel::<Vec<u8>>();
    let (dev_tx, _dev_out) = channel::<Vec<u8>>();
    let mut engine = Engine::new(
        dev_rx,
        dev_tx,
        link,
        Ipv4Address::new(10, 77, 0, 1),
        TrafficCounters::new(),
    )
    .unwrap_or_else(|e| fail(&format!("probe engine init: {e}")));
    let stop = AtomicBool::new(false);
    let t = StdInstant::now();
    let r = engine.run_probes(&stop, &mut |_| {});
    (r, t.elapsed())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    start_http_server();
    start_fake_dns();
    start_udp_echo();
    let mut skips: Vec<&str> = Vec::new();

    // The two ~60 s tests run concurrently with everything else.
    let zombie_thread = std::thread::spawn(zombie_test);
    let cleanup_thread = std::thread::spawn(udp_cleanup_test);

    // -- S1: hostile relay --------------------------------------------------
    let mut sim_r = start_simphone("127.0.0.1:47798", &[]);
    start_hostile_relay("127.0.0.1:47790", "127.0.0.1:47798");
    std::thread::sleep(Duration::from_millis(300));
    {
        let mut h = Harness::start("127.0.0.1:47790", true);
        match h.await_probes(Duration::from_secs(30)) {
            Ok(()) => {}
            Err(e) => fail(&format!("S1: probes through the hostile relay failed: {e}")),
        }
        let out = get(&mut h, "/sized?len=1048576&seed=5", 49101, Duration::from_secs(60))
            .unwrap_or_else(|e| fail(&format!("S1: {e}")));
        check(out.graceful, "S1: relayed transfer did not end gracefully");
        check(
            strip_http(&out.received) == pattern(5, 1024 * 1024).as_slice(),
            "S1: 1 MiB through the hostile relay corrupted",
        );
        h.shutdown().unwrap_or_else(|e| fail(&format!("S1: engine shutdown: {e}")));
    }
    let _ = sim_r.kill();
    let _ = sim_r.wait();
    println!("S1 OK: handshake, probes and 1 MiB survived a byte-mangling relay (adb-forward stream shape)");

    // -- Main harness --------------------------------------------------------
    let mut sim_a = start_simphone("127.0.0.1:47779", &[]);
    let mut h = Harness::start("127.0.0.1:47779", true);
    match h.await_probes(Duration::from_secs(30)) {
        Ok(()) => println!("probes OK on the main harness (gate for S2–S11)"),
        Err(e) => fail(&format!("main harness probes failed: {e}")),
    }
    // The counters must read zero: handshake and probe bytes are not
    // user traffic and must not be counted.
    let (down0, up0) = h.counters.snapshot();
    check(down0 == 0 && up0 == 0, "counters not zero after handshake + probes");

    // -- S2: 10 MiB down ------------------------------------------------------
    let out = get(&mut h, "/sized?len=10485760&seed=42", 49102, Duration::from_secs(120))
        .unwrap_or_else(|e| fail(&format!("S2: {e}")));
    let body = strip_http(&out.received);
    let want = pattern(42, 10 * 1024 * 1024);
    check(body == want.as_slice(), "S2: 10 MiB download corrupted");
    println!(
        "S2 OK: 10 MiB down byte-identical (fnv1a {:#018x})",
        fnv1a(body)
    );
    let (down1, _up1) = h.counters.snapshot();
    check(
        down1 >= 10 * 1024 * 1024,
        "S2: down counter below the transferred size",
    );
    // MTU: full-size segments must have flowed, none over the MTU.
    let max_pkt = h.max_rx.load(Ordering::Relaxed);
    check(
        max_pkt == nxcore::LINK_MTU as u64,
        "S2/S4: largest engine→app packet was not exactly the 1400-byte MTU",
    );

    // -- S2b: 1 MiB up (echo) --------------------------------------------------
    {
        let payload = pattern(6, 1024 * 1024);
        let mut req = format!(
            "POST /echo HTTP/1.1\r\nHost: 203.0.113.7\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        )
        .into_bytes();
        req.extend_from_slice(&payload);
        let out = tcp_exchange(
            &mut h,
            Ipv4Address::new(203, 0, 113, 7),
            18081,
            49103,
            &req,
            false,
            Duration::from_secs(120),
        )
        .unwrap_or_else(|e| fail(&format!("S2b: {e}")));
        check(
            strip_http(&out.received) == payload.as_slice(),
            "S2b: 1 MiB upload echo corrupted",
        );
        let (_d, up2) = h.counters.snapshot();
        check(up2 >= 1024 * 1024, "S2b: up counter below the uploaded size");
    }
    println!("S2b OK: 1 MiB up echoed back byte-identical; counters track both directions");

    // -- S3: 8 concurrent flows -------------------------------------------------
    {
        let specs: [(usize, u64); 8] = [
            (1024, 11),
            (100 * 1024, 12),
            (1024 * 1024, 13),
            (10 * 1024, 14),
            (500 * 1024, 15),
            (2 * 1024 * 1024, 16),
            (64 * 1024, 17),
            (3 * 1024 * 1024, 18),
        ];
        struct Conc {
            handle: SocketHandle,
            req: Vec<u8>,
            sent: usize,
            received: Vec<u8>,
            done: bool,
            expected: Vec<u8>,
        }
        let mut flows: Vec<Conc> = Vec::new();
        for (i, (len, seed)) in specs.iter().enumerate() {
            let mut s = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 256 * 1024]),
                tcp::SocketBuffer::new(vec![0; 16 * 1024]),
            );
            s.set_nagle_enabled(false);
            s.connect(
                h.iface.context(),
                IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 7)), 18081),
                30000 + i as u16,
            )
            .unwrap_or_else(|e| fail(&format!("S3 connect {i}: {e:?}")));
            let req = format!(
                "GET /sized?len={len}&seed={seed} HTTP/1.1\r\nHost: 203.0.113.7\r\nConnection: close\r\n\r\n"
            )
            .into_bytes();
            flows.push(Conc {
                handle: h.sockets.add(s),
                req,
                sent: 0,
                received: Vec::new(),
                done: false,
                expected: pattern(*seed, *len),
            });
        }
        let deadline = StdInstant::now() + Duration::from_secs(90);
        while StdInstant::now() < deadline && !flows.iter().all(|f| f.done) {
            h.poll();
            for f in flows.iter_mut() {
                if f.done {
                    continue;
                }
                let socket = h.sockets.get_mut::<tcp::Socket>(f.handle);
                if f.sent < f.req.len() && socket.state() == tcp::State::Established && socket.can_send() {
                    if let Ok(n) = socket.send_slice(&f.req[f.sent..]) {
                        f.sent += n;
                    }
                }
                {
                    let mut buf = [0u8; 32768];
                    match socket.recv_slice(&mut buf) {
                        Ok(0) => {}
                        Ok(n) => f.received.extend_from_slice(&buf[..n]),
                        Err(tcp::RecvError::Finished) => f.done = true,
                        Err(_) => {}
                    }
                }
                if socket.state() == tcp::State::Closed {
                    f.done = true;
                }
            }
        }
        for (i, f) in flows.iter().enumerate() {
            check(f.done, &format!("S3: flow {i} stalled (not done at the deadline)"));
            check(
                strip_http(&f.received) == f.expected.as_slice(),
                &format!("S3: flow {i} body corrupted or cross-contaminated"),
            );
            h.sockets.remove(f.handle);
        }
    }
    println!("S3 OK: 8 concurrent flows (1 KiB – 3 MiB) all byte-identical, no stall");

    // -- S4: MTU edge payloads ---------------------------------------------------
    for (i, n) in [1399usize, 1400, 1401].iter().enumerate() {
        let payload = pattern(21, *n);
        let mut req = format!(
            "POST /echo HTTP/1.1\r\nHost: 203.0.113.7\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        )
        .into_bytes();
        req.extend_from_slice(&payload);
        let out = tcp_exchange(
            &mut h,
            Ipv4Address::new(203, 0, 113, 7),
            18081,
            49110 + i as u16,
            &req,
            false,
            Duration::from_secs(30),
        )
        .unwrap_or_else(|e| fail(&format!("S4 ({n} bytes): {e}")));
        check(
            strip_http(&out.received) == payload.as_slice(),
            &format!("S4: {n}-byte payload corrupted"),
        );
    }
    check(
        h.max_rx.load(Ordering::Relaxed) <= nxcore::LINK_MTU as u64,
        "S4: an engine packet exceeded the 1400-byte MTU",
    );
    println!("S4 OK: payloads of 1399/1400/1401 bytes intact; no packet over the 1400-byte MTU");

    // -- S5: DNS — multiple names + NXDOMAIN --------------------------------------
    {
        let answers = dns_batch(
            &mut h,
            53124,
            Ipv4Address::new(203, 0, 113, 53),
            &[
                (0xA001, "one.test"),
                (0xA002, "two.three.test"),
                (0xA003, "deep.a.b.test"),
                (0xA004, "gone.nx.test"),
            ],
            Duration::from_secs(15),
        );
        for txid in [0xA001u16, 0xA002, 0xA003] {
            match answers.get(&txid) {
                Some((rcode, an, tail)) => {
                    check(*rcode == 0 && *an >= 1 && tail == &vec![203, 0, 113, 99],
                        &format!("S5: bad answer for txid {txid:#x}"));
                }
                None => fail(&format!("S5: no intercepted answer for txid {txid:#x}")),
            }
        }
        match answers.get(&0xA004) {
            Some((rcode, an, _)) => {
                check(*rcode == 3 && *an == 0, "S5: NXDOMAIN answer mangled in transit");
            }
            None => fail("S5: NXDOMAIN answer never arrived"),
        }
    }
    println!("S5 OK: 3 names resolved via interception; NXDOMAIN passed through with rcode 3");

    // -- S8: flow churn -------------------------------------------------------------
    {
        let t = StdInstant::now();
        for i in 0..500u16 {
            let out = get(&mut h, "/sized?len=64&seed=7", 20000 + i, Duration::from_secs(10))
                .unwrap_or_else(|e| fail(&format!("S8: cycle {i}: {e}")));
            check(
                strip_http(&out.received) == pattern(7, 64).as_slice(),
                &format!("S8: cycle {i} body corrupted"),
            );
        }
        println!("S8 OK: 500 open/close cycles in {:.1?}", t.elapsed());
    }

    // -- S9: destination RST mid-transfer --------------------------------------------
    {
        let out = get(&mut h, "/rst", 49120, Duration::from_secs(30))
            .unwrap_or_else(|e| fail(&format!("S9: {e}")));
        check(!out.graceful, "S9: a reset transfer looked graceful");
        check(out.reset, "S9: app never observed the reset");
        check(
            out.received.len() < 100_000,
            "S9: app somehow received the full claimed body despite the RST",
        );
        let out = get(&mut h, "/hello", 49121, Duration::from_secs(20))
            .unwrap_or_else(|e| fail(&format!("S9 follow-up flow: {e}")));
        check(
            strip_http(&out.received) == &b"nexlink-strict-ok"[..],
            "S9: engine did not survive the RST",
        );
    }
    println!("S9 OK: mid-transfer RST surfaced as a reset; engine healthy afterwards");

    // -- S10: half-close --------------------------------------------------------------
    {
        let mut req = format!(
            "POST /afterfin?len=50000&seed=9 HTTP/1.1\r\nHost: 203.0.113.7\r\nContent-Length: 1000\r\n\r\n"
        )
        .into_bytes();
        req.extend_from_slice(&pattern(8, 1000));
        let out = tcp_exchange(
            &mut h,
            Ipv4Address::new(203, 0, 113, 7),
            18081,
            49122,
            &req,
            true,
            Duration::from_secs(30),
        )
        .unwrap_or_else(|e| fail(&format!("S10: {e}")));
        check(out.graceful, "S10: half-closed flow did not end gracefully");
        check(
            strip_http(&out.received) == pattern(9, 50000).as_slice(),
            "S10: response after the app FIN was truncated or corrupted",
        );
    }
    println!("S10 OK: full 50 KiB response delivered after the app's half-close (FIN)");

    // -- S11: link severed mid-transfer --------------------------------------------------
    {
        // Start a 10 MiB download in a side thread of the app stack by
        // driving manually until some bytes land, then kill the phone.
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 256 * 1024]),
            tcp::SocketBuffer::new(vec![0; 16 * 1024]),
        );
        sock.connect(
            h.iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 7)), 18081),
            49123,
        )
        .unwrap_or_else(|e| fail(&format!("S11 connect: {e:?}")));
        let handle = h.sockets.add(sock);
        let mut sent = false;
        let mut got = 0usize;
        let deadline = StdInstant::now() + Duration::from_secs(30);
        while StdInstant::now() < deadline && got < 65536 {
            h.poll();
            let socket = h.sockets.get_mut::<tcp::Socket>(handle);
            if !sent && socket.state() == tcp::State::Established {
                socket
                    .send_slice(b"GET /sized?len=10485760&seed=42 HTTP/1.1\r\nHost: 203.0.113.7\r\nConnection: close\r\n\r\n")
                    .unwrap_or_else(|e| fail(&format!("S11 send: {e:?}")));
                sent = true;
            }
            {
                let mut buf = [0u8; 16384];
                if let Ok(n) = socket.recv_slice(&mut buf) {
                    got += n;
                }
            }
        }
        check(sent && got >= 65536, "S11: bulk flow never got going");
        let _ = sim_a.kill();
        let _ = sim_a.wait();
        let t_kill = StdInstant::now();
        match h.engine.run_rx.recv_timeout(Duration::from_secs(15)) {
            Ok(Err(e)) => {
                // Any of the link-death errors is correct: a clean FIN
                // gives "phone closed the link", but a process killed
                // with data in flight makes the OS deliver RST instead
                // ("Connection reset by peer") — which string appears is
                // OS timing, not engine behavior. What matters: an
                // explicit error, promptly (the recv_timeout above).
                let msg = e.to_string();
                check(
                    msg.contains("phone closed the link")
                        || msg.contains("Connection reset")
                        || msg.contains("link is dead"),
                    &format!("S11: unexpected engine error: {e}"),
                );
                println!(
                    "S11 OK: severed link reported in {:.1?} (\"{e}\")",
                    t_kill.elapsed()
                );
            }
            Ok(Ok(())) => fail("S11: engine exited cleanly after its link was severed"),
            Err(_) => fail("S11: engine did not notice the severed link within 15 s"),
        }
        h.sockets.remove(handle);
        drop(h);
        // Recovery: a fresh phone + engine must work immediately.
        std::thread::sleep(Duration::from_millis(400));
        let mut sim_a2 = start_simphone("127.0.0.1:47779", &[]);
        let mut h2 = Harness::start("127.0.0.1:47779", true);
        match h2.await_probes(Duration::from_secs(30)) {
            Ok(()) => {}
            Err(e) => fail(&format!("S11 recovery probes: {e}")),
        }
        let out = get(&mut h2, "/hello", 49124, Duration::from_secs(20))
            .unwrap_or_else(|e| fail(&format!("S11 recovery: {e}")));
        check(strip_http(&out.received) == &b"nexlink-strict-ok"[..], "S11: recovery flow corrupted");
        h2.shutdown().unwrap_or_else(|e| fail(&format!("S11 recovery shutdown: {e}")));
        let _ = sim_a2.kill();
        let _ = sim_a2.wait();
    }
    println!("S11 OK: fresh tunnel after the sever works (probes + flow)");

    // -- S6: DNS with a dead upstream -------------------------------------------------------
    {
        let mut sim_e = start_simphone("127.0.0.1:47794", &["--dns", "127.0.0.1:1"]);
        let mut he = Harness::start("127.0.0.1:47794", false);
        let answers = dns_batch(
            &mut he,
            53125,
            Ipv4Address::new(203, 0, 113, 53),
            &[(0xB001, "one.test")],
            Duration::from_secs(8),
        );
        check(answers.is_empty(), "S6: a dead upstream resolver produced an answer?!");
        let out = get(&mut he, "/hello", 49130, Duration::from_secs(20))
            .unwrap_or_else(|e| fail(&format!("S6 follow-up flow: {e}")));
        check(
            strip_http(&out.received) == &b"nexlink-strict-ok"[..],
            "S6: engine poisoned by the dead DNS upstream",
        );
        he.shutdown().unwrap_or_else(|e| fail(&format!("S6 shutdown: {e}")));
        let _ = sim_e.kill();
        let _ = sim_e.wait();
    }
    println!("S6 OK: dead DNS upstream → clean app-side timeout, engine unaffected");

    // -- S7: probe negative tests --------------------------------------------------------------
    {
        // (a) The phone's resolver is dead: no DNS answer ever comes.
        let mut sim_b = start_simphone("127.0.0.1:47791", &["--dns", "127.0.0.1:1"]);
        let (r, elapsed) = probe_once("127.0.0.1:47791", None);
        match r {
            Err(e) => {
                check(e.starts_with("DNS check failed"), &format!("S7a: wrong stage named: {e}"));
                check(
                    elapsed >= Duration::from_secs(10) && elapsed <= Duration::from_secs(25),
                    &format!("S7a: probes returned after {elapsed:?}, expected ~12 s timeout"),
                );
            }
            Ok(()) => fail("S7a: probes PASSED with a dead resolver"),
        }
        let _ = sim_b.kill();
        let _ = sim_b.wait();
        println!("S7a OK: dead resolver → \"DNS check failed\" after {elapsed:.0?}");

        // (b) DNS works, the traffic destination refuses.
        let mut sim_c = start_simphone("127.0.0.1:47792", &["--map", "1.1.1.1:443=127.0.0.1:1"]);
        let (r, elapsed) = probe_once("127.0.0.1:47792", None);
        match r {
            Err(e) => {
                check(
                    e.starts_with("Traffic check failed"),
                    &format!("S7b: wrong stage named: {e}"),
                );
                check(elapsed <= Duration::from_secs(25), &format!("S7b: took {elapsed:?}"));
            }
            Ok(()) => fail("S7b: probes PASSED with a refused TCP destination"),
        }
        let _ = sim_c.kill();
        let _ = sim_c.wait();
        println!("S7b OK: refused destination → \"Traffic check failed\" after {elapsed:.0?}");

        // (c) The link dies between handshake and probes.
        let mut sim_d = start_simphone("127.0.0.1:47793", &[]);
        let (r, elapsed) = probe_once("127.0.0.1:47793", Some(&mut sim_d));
        match r {
            Err(e) => {
                check(e.starts_with("DNS check failed"), &format!("S7c: wrong stage named: {e}"));
                check(
                    elapsed <= Duration::from_secs(10),
                    &format!("S7c: took {elapsed:?} — a dead link must fail promptly, not at the timeout"),
                );
            }
            Ok(()) => fail("S7c: probes PASSED over a dead link"),
        }
        println!("S7c OK: link killed pre-probe → named stage error in {elapsed:.0?}");
    }

    // -- S13: UDP via the NXLP double ------------------------------------------------------------
    match udp_double_test() {
        Ok(msg) => println!("S13 OK: {msg}"),
        Err(e) => fail(&format!("S13: {e}")),
    }

    // -- S14: UDP via simphone to a real UDP echo server (environment gated) ----------------------
    if udp_loopback_works() {
        let mut sim_u = start_simphone("127.0.0.1:47799", &[]);
        let mut hu = Harness::start("127.0.0.1:47799", false);
        let mut sock = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
        );
        sock.bind(54546).unwrap_or_else(|e| fail(&format!("S14 bind: {e:?}")));
        let handle = hu.sockets.add(sock);
        let payload = pattern(55, 1000);
        {
            let socket = hu.sockets.get_mut::<udp::Socket>(handle);
            socket
                .send_slice(
                    &payload,
                    IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 8)), 5353),
                )
                .unwrap_or_else(|e| fail(&format!("S14 send: {e:?}")));
        }
        let mut echoed: Option<Vec<u8>> = None;
        let end = StdInstant::now() + Duration::from_secs(15);
        while StdInstant::now() < end && echoed.is_none() {
            hu.poll();
            let socket = hu.sockets.get_mut::<udp::Socket>(handle);
            if let Ok((data, _)) = socket.recv() {
                echoed = Some(data.to_vec());
            }
        }
        hu.sockets.remove(handle);
        check(echoed.as_deref() == Some(payload.as_slice()), "S14: UDP echo corrupted");
        hu.shutdown().unwrap_or_else(|e| fail(&format!("S14 shutdown: {e}")));
        let _ = sim_u.kill();
        let _ = sim_u.wait();
        println!("S14 OK: UDP echo through simphone's real DatagramSocket relay");
    } else {
        skips.push("S14");
        println!("S14 SKIP: this sandbox refuses every UDP send (EPERM, even on loopback) — simphone's real-UDP leg cannot run here; the engine's UDP handling is covered by S13/S15");
    }

    // -- The two long-running thread tests ----------------------------------------------------------
    match zombie_thread.join() {
        Ok(Ok(msg)) => println!("S12 OK: {msg}"),
        Ok(Err(e)) => fail(&format!("S12: {e}")),
        Err(_) => fail("S12: zombie test thread panicked"),
    }
    match cleanup_thread.join() {
        Ok(Ok(msg)) => println!("S15 OK: {msg}"),
        Ok(Err(e)) => fail(&format!("S15: {e}")),
        Err(_) => fail("S15: cleanup test thread panicked"),
    }

    if skips.is_empty() {
        println!("STRICT E2E PASS (no skips)");
    } else {
        println!("STRICT E2E PASS ({} environmental skip: {})", skips.len(), skips.join(", "));
    }
}
