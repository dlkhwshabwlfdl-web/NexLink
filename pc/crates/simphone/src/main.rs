//! simphone — a simulated NexLink phone for development and testing.
//!
//! It implements the phone half of NXLP with ordinary host sockets, exactly
//! the way the Android app does:
//!   * TCP flow  -> a real TcpStream to the destination, bytes copied both ways
//!   * UDP flow  -> a DatagramSocket association
//!   * UDP to port 53 is *intercepted*: the datagram is sent to the phone's
//!     own resolver endpoint (`--dns`) instead of the dialed address, which
//!     is what makes the PC inherit the phone's DNS in the real app.
//!
//! Test hooks:
//!   --armed=false        answer HELLO_ACK with armed = false
//!   --map A:PA=B:PB      rewrite a destination (repeatable), so tests can
//!                        point TEST-NET addresses at local servers
//!   --dns IP:PORT        resolver endpoint for intercepted DNS flows
//!
//! Intercepted DNS queries are sent to the resolver over UDP, falling back
//! to DNS-over-TCP (RFC 7766) when UDP is unavailable — some sandboxes and
//! networks block UDP outright; the Muse VM is one of them, which is why
//! the fallback exists and why the e2e test exercises it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nxcore::proto::*;

struct Config {
    listen: String,
    armed: bool,
    map: HashMap<(String, u16), String>,
    dns: Option<String>,
}

fn parse_args() -> Config {
    let mut cfg = Config { listen: "127.0.0.1:47777".into(), armed: true, map: HashMap::new(), dns: None };
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => { cfg.listen = args[i + 1].clone(); i += 2; }
            "--armed" => { cfg.armed = args[i + 1] != "false"; i += 2; }
            "--dns" => { cfg.dns = Some(args[i + 1].clone()); i += 2; }
            "--map" => {
                let (from, to) = args[i + 1].split_once('=').expect("--map FROM=TO");
                let (ip, port) = from.rsplit_once(':').expect("--map FROM is IP:PORT");
                cfg.map.insert((ip.to_string(), port.parse().expect("map port")), to.to_string());
                i += 2;
            }
            other => { eprintln!("simphone: unknown argument {other}"); std::process::exit(2); }
        }
    }
    cfg
}

fn send_frame(link: &Mutex<TcpStream>, frame: &Frame) {
    let mut buf = Vec::with_capacity(1024);
    frame.encode(&mut buf);
    let mut stream = link.lock().unwrap();
    let _ = stream.write_all(&buf);
}

enum Flow {
    Tcp(TcpStream),
    Udp(Arc<UdpSocket>, Arc<AtomicBool>),
    /// An intercepted DNS flow: queries are answered by the phone's
    /// resolver (see `--dns`), not relayed to the dialed address.
    Dns,
}

fn main() {
    let cfg = Arc::new(parse_args());
    let listener = TcpListener::bind(&cfg.listen).unwrap_or_else(|e| {
        eprintln!("simphone: cannot listen on {}: {e}", cfg.listen);
        std::process::exit(1);
    });
    eprintln!("simphone: listening on {} (armed={})", cfg.listen, cfg.armed);
    let (stream, peer) = listener.accept().expect("accept");
    eprintln!("simphone: link from {peer}");
    run_session(stream, cfg);
}

fn run_session(link_stream: TcpStream, cfg: Arc<Config>) {
    let link = Arc::new(Mutex::new(link_stream.try_clone().unwrap()));
    let mut reader_stream = link_stream;
    let flows: Arc<Mutex<HashMap<u32, Flow>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut fr = FrameReader::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = match reader_stream.read(&mut chunk) {
            Ok(0) => { eprintln!("simphone: link closed"); return; }
            Ok(n) => n,
            Err(e) => { eprintln!("simphone: link read error: {e}"); return; }
        };
        fr.feed(&chunk[..n]);
        while let Ok(Some(frame)) = fr.next_frame() {
            match frame {
                Frame::Hello { .. } => {
                    send_frame(&link, &Frame::HelloAck { armed: cfg.armed, name: "simphone".into() });
                }
                Frame::Open { flow, proto, ip, port } => {
                    if !cfg.armed {
                        send_frame(&link, &Frame::OpenErr { flow, code: ERR_NOT_ARMED });
                        continue;
                    }
                    let ip_str = std::net::Ipv4Addr::from(ip).to_string();
                    let dest = cfg.map.get(&(ip_str.clone(), port)).cloned()
                        .unwrap_or_else(|| format!("{ip_str}:{port}"));
                    match proto {
                        PROTO_TCP => open_tcp(flow, &dest, &link, &flows),
                        PROTO_UDP => open_udp(flow, &dest, port, &cfg, &link, &flows),
                        _ => send_frame(&link, &Frame::OpenErr { flow, code: ERR_CONNECT_FAILED }),
                    }
                }
                Frame::Data { flow, data } => {
                    enum Act {
                        Tcp(TcpStream),
                        Udp(Arc<UdpSocket>),
                        Dns,
                        None,
                    }
                    let act = {
                        let g = flows.lock().unwrap();
                        match g.get(&flow) {
                            Some(Flow::Tcp(s)) => Act::Tcp(s.try_clone().unwrap()),
                            Some(Flow::Udp(s, _)) => Act::Udp(s.clone()),
                            Some(Flow::Dns) => Act::Dns,
                            None => Act::None,
                        }
                    };
                    match act {
                        Act::Tcp(mut s) => {
                            if s.write_all(&data).is_err() {
                                flows.lock().unwrap().remove(&flow);
                                send_frame(&link, &Frame::Close { flow, flags: CLOSE_RST });
                            }
                        }
                        Act::Udp(sock) => {
                            let r = sock.send(&data);
                            eprintln!("simphone: udp flow {flow} data {} bytes -> socket: {r:?}", data.len());
                        }
                        Act::Dns => {
                            let resolver = cfg.dns.clone().expect("dns flow without resolver");
                            let link = link.clone();
                            std::thread::spawn(move || answer_dns_query(flow, &data, &resolver, &link));
                        }
                        Act::None => {}
                    }
                }
                Frame::Close { flow, flags } => {
                    if let Some(f) = flows.lock().unwrap().remove(&flow) {
                        match f {
                            Flow::Tcp(sock) => {
                                let _ = sock.shutdown(if flags & CLOSE_RST != 0 { Shutdown::Both } else { Shutdown::Write });
                            }
                            Flow::Udp(_, alive) => alive.store(false, Ordering::Relaxed),
                            Flow::Dns => {}
                        }
                    }
                }
                Frame::Ping => send_frame(&link, &Frame::Pong),
                Frame::Pong => {}
                Frame::Bye => { eprintln!("simphone: bye"); return; }
                Frame::HelloAck { .. } | Frame::OpenOk { .. } | Frame::OpenErr { .. } => {}
            }
        }
    }
}

/// Resolve one intercepted DNS query with the phone's resolver: UDP first,
/// DNS-over-TCP as the fallback for networks where UDP is blocked.
fn answer_dns_query(flow: u32, query: &[u8], resolver: &str, link: &Arc<Mutex<TcpStream>>) {
    fn via_udp(resolver: &str, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(resolver)?;
        sock.set_read_timeout(Some(Duration::from_secs(2)))?;
        sock.send(query)?;
        let mut buf = [0u8; 4096];
        let n = sock.recv(&mut buf)?;
        Ok(buf[..n].to_vec())
    }
    fn via_tcp(resolver: &str, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut s = TcpStream::connect(resolver)?;
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        s.write_all(&(query.len() as u16).to_be_bytes())?;
        s.write_all(query)?;
        let mut len_buf = [0u8; 2];
        s.read_exact(&mut len_buf)?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf)?;
        Ok(buf)
    }
    let answer = via_udp(resolver, query).or_else(|_| via_tcp(resolver, query));
    match answer {
        Ok(bytes) => {
            eprintln!("simphone: dns flow {flow} answered ({} bytes)", bytes.len());
            send_frame(link, &Frame::Data { flow, data: bytes });
        }
        Err(e) => eprintln!("simphone: dns flow {flow} resolution failed: {e}"),
    }
}

fn open_tcp(flow: u32, dest: &str, link: &Arc<Mutex<TcpStream>>, flows: &Arc<Mutex<HashMap<u32, Flow>>>) {
    match TcpStream::connect(dest) {
        Ok(sock) => {
            let _ = sock.set_nodelay(true);
            flows.lock().unwrap().insert(flow, Flow::Tcp(sock.try_clone().unwrap()));
            send_frame(link, &Frame::OpenOk { flow });
            let link = link.clone();
            let flows = flows.clone();
            let mut reader = sock;
            std::thread::spawn(move || {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => {
                            flows.lock().unwrap().remove(&flow);
                            send_frame(&link, &Frame::Close { flow, flags: CLOSE_FIN });
                            return;
                        }
                        Ok(n) => send_frame(&link, &Frame::Data { flow, data: buf[..n].to_vec() }),
                        Err(_) => {
                            flows.lock().unwrap().remove(&flow);
                            send_frame(&link, &Frame::Close { flow, flags: CLOSE_RST });
                            return;
                        }
                    }
                }
            });
        }
        Err(e) => {
            eprintln!("simphone: connect {dest} failed: {e}");
            send_frame(link, &Frame::OpenErr { flow, code: ERR_CONNECT_FAILED });
        }
    }
}

fn open_udp(flow: u32, dest: &str, dest_port: u16, cfg: &Arc<Config>, link: &Arc<Mutex<TcpStream>>, flows: &Arc<Mutex<HashMap<u32, Flow>>>) {
    // DNS interception: port-53 flows are answered by the phone's resolver,
    // never relayed to the dialed address.
    if dest_port == 53 && cfg.dns.is_some() {
        eprintln!("simphone: flow {flow} is DNS — intercepted (dialed {dest})");
        flows.lock().unwrap().insert(flow, Flow::Dns);
        send_frame(link, &Frame::OpenOk { flow });
        return;
    }
    let target: String = dest.to_string();
    let target_addr: SocketAddr = match target.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("simphone: bad UDP target {target}: {e}");
            send_frame(link, &Frame::OpenErr { flow, code: ERR_CONNECT_FAILED });
            return;
        }
    };
    eprintln!("simphone: udp flow {flow} -> {target_addr} (dialed {dest})");
    match UdpSocket::bind("0.0.0.0:0").and_then(|s| s.connect(target_addr).map(|_| s)) {
        Ok(sock) => {
            let sock = Arc::new(sock);
            let alive = Arc::new(AtomicBool::new(true));
            flows.lock().unwrap().insert(flow, Flow::Udp(sock.clone(), alive.clone()));
            send_frame(link, &Frame::OpenOk { flow });
            let link = link.clone();
            std::thread::spawn(move || {
                let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
                let mut buf = [0u8; 64 * 1024];
                while alive.load(Ordering::Relaxed) {
                    match sock.recv(&mut buf) {
                        Ok(n) => {
                            eprintln!("simphone: udp flow {flow} reply {n} bytes -> link");
                            send_frame(&link, &Frame::Data { flow, data: buf[..n].to_vec() });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
                        Err(_) => return,
                    }
                }
            });
        }
        Err(e) => {
            eprintln!("simphone: UDP bind/connect {target} failed: {e}");
            send_frame(link, &Frame::OpenErr { flow, code: ERR_CONNECT_FAILED });
        }
    }
}
