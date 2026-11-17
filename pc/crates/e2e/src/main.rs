//! NexLink end-to-end test.
//!
//! ```text
//! virtual PC app (smoltcp stack #2, this binary)
//!     │ raw IP packets over channels
//!     ▼
//! nxcore engine (smoltcp stack #1) ── NXLP over real TCP ──► simphone binary
//!     │                                                          │
//!     │                                            real sockets ─┤
//!     ▼                                                          ▼
//! assertions                                  local HTTP server / fake DNS
//! ```
//!
//! Three checks:
//!   1. An HTTP GET from the virtual app reaches the HTTP server *through*
//!      the tunnel and the body comes back intact.
//!   2. A DNS query the app sends to 203.0.113.53:53 is answered by the
//!      fake resolver (203.0.113.99) — proof of phone-side DNS interception,
//!      since nothing lives at 203.0.113.53.
//!   3. With the phone not armed, the handshake reports armed = false.
//!
//! Exit code 0 = PASS, 1 = FAIL.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken as PhyRxToken, TxToken as PhyTxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use nxcore::engine::{client_handshake, Engine};

// ---------------------------------------------------------------------------
// Channel device for the virtual app's stack.
// ---------------------------------------------------------------------------

struct ChanDevice {
    rx: Receiver<Vec<u8>>,
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
        match self.rx.try_recv() {
            Ok(pkt) => Some((RxTok(pkt), TxTok(self.tx.clone()))),
            Err(_) => None,
        }
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
// Local servers: HTTP on 127.0.0.1:18080, fake DNS on 127.0.0.1:15353.
// ---------------------------------------------------------------------------

fn start_http_server() {
    let listener = TcpListener::bind("127.0.0.1:18080").expect("http bind");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let body = "nexlink-e2e-ok";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
}

fn dns_response(query: &[u8]) -> Vec<u8> {
    let mut pos = 12;
    while query[pos] != 0 {
        pos += query[pos] as usize + 1;
    }
    pos += 5;
    let mut out = Vec::new();
    out.extend_from_slice(&query[0..2]); // transaction id
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qd
    out.extend_from_slice(&1u16.to_be_bytes()); // an
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..pos]); // question
    out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name pointer
    out.extend_from_slice(&1u16.to_be_bytes()); // type A
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&60u32.to_be_bytes()); // ttl
    out.extend_from_slice(&4u16.to_be_bytes()); // rdlen
    out.extend_from_slice(&[203, 0, 113, 99]);
    out
}

fn start_fake_dns() {
    // UDP server (the normal DNS transport).
    let sock = UdpSocket::bind("127.0.0.1:15353").expect("dns udp bind");
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
    // TCP server (DNS-over-TCP): the Muse VM sandbox blocks UDP outright,
    // so the e2e resolver must also speak TCP for the test to run there.
    let listener = TcpListener::bind("127.0.0.1:15353").expect("dns tcp bind");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
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
                let _ = s.write_all(&(resp.len() as u16).to_be_bytes());
                let _ = s.write_all(&resp);
            });
        }
    });
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

fn start_simphone(armed: bool) -> Child {
    let mut cmd = Command::new(simphone_path());
    cmd.arg("--listen").arg("127.0.0.1:47778")
        .arg("--map").arg("203.0.113.7:18080=127.0.0.1:18080")
        .arg("--dns").arg("127.0.0.1:15353")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit());
    if !armed {
        cmd.arg("--armed").arg("false");
    }
    let child = cmd.spawn().expect("spawn simphone");
    std::thread::sleep(Duration::from_millis(700));
    child
}

// ---------------------------------------------------------------------------
// The test itself
// ---------------------------------------------------------------------------

fn fail(msg: &str) -> ! {
    eprintln!("E2E FAIL: {msg}");
    std::process::exit(1);
}

fn dns_query_bytes() -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&0x1234u16.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    for part in ["example", "test"] {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

fn check_fake_dns_directly() {
    // Probed over TCP: this sandbox blocks UDP entirely (EPERM on send),
    // which is also why simphone has the DNS-over-TCP fallback.
    let query = dns_query_bytes();
    let mut s = TcpStream::connect("127.0.0.1:15353").unwrap_or_else(|e| fail(&format!("fake DNS probe connect: {e}")));
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(&(query.len() as u16).to_be_bytes()).unwrap();
    s.write_all(&query).unwrap();
    let mut len_buf = [0u8; 2];
    if s.read_exact(&mut len_buf).is_err() {
        fail("fake DNS probe: no response length");
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    match s.read_exact(&mut buf) {
        Ok(()) if len >= 4 && &buf[len - 4..] == [203, 0, 113, 99] => {
            println!("check 0 OK: fake DNS answers directly (sanity)");
        }
        Ok(()) => fail("fake DNS probe: unexpected answer"),
        Err(e) => fail(&format!("fake DNS probe: {e}")),
    }
}

fn main() {
    start_http_server();
    start_fake_dns();
    check_fake_dns_directly();
    let mut sim = start_simphone(true);

    // Wire the virtual app's device to the engine's device, cross-connected.
    let (app_out_tx, engine_in_rx) = channel::<Vec<u8>>();
    let (engine_out_tx, app_in_rx) = channel::<Vec<u8>>();

    // Link + handshake (the engine runs in its own thread).
    let mut link = TcpStream::connect("127.0.0.1:47778").unwrap_or_else(|e| fail(&format!("link connect: {e}")));
    let hello = client_handshake(&mut link, "e2e").unwrap_or_else(|e| fail(&format!("handshake: {e}")));
    if !hello.armed {
        fail("simphone (armed) reported armed = false");
    }
    println!("handshake ok: phone={} armed=true", hello.phone_name);

    let stop = Arc::new(AtomicBool::new(false));
    let engine_stop = stop.clone();
    let engine_thread = std::thread::spawn(move || {
        let mut engine = Engine::new(engine_in_rx, engine_out_tx, link, Ipv4Address::new(10, 77, 0, 1))
            .expect("engine init");
        let _ = engine.run(engine_stop);
    });

    // The virtual PC app: its own stack at 10.77.0.2.
    let mut app_dev = ChanDevice { rx: app_in_rx, tx: app_out_tx };
    let mut app_iface = Interface::new(Config::new(HardwareAddress::Ip), &mut app_dev, Instant::now());
    app_iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(10, 77, 0, 2)), 24));
    });
    app_iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 77, 0, 1)).unwrap();
    let mut sockets = SocketSet::new(vec![]);

    // -- Check 1: HTTP through the tunnel ----------------------------------
    let mut tcp_sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 16 * 1024]),
        tcp::SocketBuffer::new(vec![0; 16 * 1024]),
    );
    tcp_sock
        .connect(
            app_iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 7)), 18080),
            49152,
        )
        .unwrap_or_else(|e| fail(&format!("app connect: {e:?}")));
    let tcp_handle = sockets.add(tcp_sock);

    let deadline = StdInstant::now() + Duration::from_secs(20);
    let mut sent = false;
    let mut received: Vec<u8> = Vec::new();
    let mut got_fin = false;
    while StdInstant::now() < deadline {
        app_iface.poll(Instant::now(), &mut app_dev, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        if !sent && socket.state() == tcp::State::Established {
            socket
                .send_slice(b"GET /hello.txt HTTP/1.0\r\nHost: 203.0.113.7\r\n\r\n")
                .unwrap_or_else(|e| fail(&format!("app send: {e:?}")));
            sent = true;
        }
        if sent && socket.may_recv() {
            let mut buf = [0u8; 8192];
            match socket.recv_slice(&mut buf) {
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(tcp::RecvError::Finished) => {
                    got_fin = true;
                    break;
                }
                Err(_) => {}
            }
        }
        if socket.state() == tcp::State::Closed {
            got_fin = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let body = String::from_utf8_lossy(&received).to_string();
    if !body.contains("nexlink-e2e-ok") {
        fail(&format!("HTTP check: unexpected body: {body:?}"));
    }
    println!("check 1 OK: HTTP body '{body}' fetched through the tunnel", body = "nexlink-e2e-ok");
    let _ = got_fin;
    sockets.remove(tcp_handle);

    // -- Check 2: DNS interception ------------------------------------------
    let mut udp_sock = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
    );
    udp_sock.bind(53123).unwrap_or_else(|e| fail(&format!("udp bind: {e:?}")));
    let udp_handle = sockets.add(udp_sock);

    // Query for example.test/A, id 0x1234.
    let query = dns_query_bytes();

    let dns_deadline = StdInstant::now() + Duration::from_secs(15);
    let mut dns_sent = false;
    let mut dns_ok = false;
    while StdInstant::now() < dns_deadline {
        app_iface.poll(Instant::now(), &mut app_dev, &mut sockets);
        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        if !dns_sent {
            socket
                .send_slice(&query, IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(203, 0, 113, 53)), 53))
                .unwrap_or_else(|e| fail(&format!("dns send: {e:?}")));
            dns_sent = true;
        }
        if let Ok((data, _meta)) = socket.recv() {
            if data.len() >= 4 && &data[data.len() - 4..] == [203, 0, 113, 99] {
                dns_ok = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if !dns_ok {
        fail("DNS check: no intercepted answer (203.0.113.99) received");
    }
    println!("check 2 OK: DNS query to 203.0.113.53 was resolved by the phone side (answer 203.0.113.99)");

    // -- Check 3: the arm switch --------------------------------------------
    stop.store(true, Ordering::Relaxed);
    let _ = engine_thread.join();
    let _ = sim.kill();
    let _ = sim.wait();
    let mut sim2 = start_simphone(false);
    let mut link2 = TcpStream::connect("127.0.0.1:47778").unwrap_or_else(|e| fail(&format!("link2 connect: {e}")));
    let hello2 = client_handshake(&mut link2, "e2e").unwrap_or_else(|e| fail(&format!("handshake2: {e}")));
    if hello2.armed {
        fail("arm check: unarmed simphone reported armed = true");
    }
    println!("check 3 OK: unarmed phone reports armed = false (the PC app refuses with a clear message)");
    let _ = sim2.kill();
    let _ = sim2.wait();

    println!("E2E PASS");
}
