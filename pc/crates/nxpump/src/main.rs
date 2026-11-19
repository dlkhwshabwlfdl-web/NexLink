//! nxpump — development harness for the NexLink engine.
//!
//! Creates a TUN device, wires it to the engine, dials the phone (or the
//! simulated phone) over TCP, handshakes, and pumps until stopped.
//! Press Enter (or close stdin) to stop.
//!
//! Usage:
//!   nxpump --tun nx0 --addr 10.77.0.2 --gateway 10.77.0.1 --link 127.0.0.1:47777

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;

use nxcore::engine::{client_handshake, Engine, TrafficCounters};
use nxcore::Ipv4Address;

struct Args {
    tun: String,
    addr: String,
    gateway: String,
    link: String,
}

fn parse_args() -> Args {
    let mut a = Args { tun: "nx0".into(), addr: "10.77.0.2".into(), gateway: "10.77.0.1".into(), link: "127.0.0.1:47777".into() };
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tun" => { a.tun = args[i + 1].clone(); i += 2; }
            "--addr" => { a.addr = args[i + 1].clone(); i += 2; }
            "--gateway" => { a.gateway = args[i + 1].clone(); i += 2; }
            "--link" => { a.link = args[i + 1].clone(); i += 2; }
            other => { eprintln!("nxpump: unknown argument {other}"); std::process::exit(2); }
        }
    }
    a
}

fn create_tun(name: &str) -> std::io::Result<File> {
    let file = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;
    // struct ifreq: 16-byte name, then u16 flags.
    let mut ifr = [0u8; 40];
    let name_bytes = name.as_bytes();
    ifr[..name_bytes.len()].copy_from_slice(name_bytes);
    let flags: u16 = 0x0001 /* IFF_TUN */ | 0x1000 /* IFF_NO_PI */;
    ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
    let ret = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, ifr.as_mut_ptr() as *mut libc::c_void) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

use std::os::unix::io::AsRawFd;

fn run_ip(args: &[&str]) {
    let status = Command::new("ip").args(args).status().expect("run ip");
    if !status.success() {
        eprintln!("nxpump: 'ip {}' failed", args.join(" "));
        std::process::exit(1);
    }
}

fn main() {
    let args = parse_args();

    let tun = create_tun(&args.tun).unwrap_or_else(|e| {
        eprintln!("nxpump: cannot create TUN {}: {e} (need root / CAP_NET_ADMIN)", args.tun);
        std::process::exit(1);
    });
    run_ip(&["addr", "add", &format!("{}/24", args.addr), "dev", &args.tun]);
    run_ip(&["link", "set", &args.tun, "up", "mtu", &nxcore::LINK_MTU.to_string()]);
    eprintln!("nxpump: {} is up at {}/24", args.tun, args.addr);

    // Device pump threads: TUN <-> channels.
    let (to_engine_tx, to_engine_rx) = channel::<Vec<u8>>();
    let (from_engine_tx, from_engine_rx) = channel::<Vec<u8>>();
    let mut tun_reader = tun.try_clone().unwrap();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 2048];
        loop {
            match tun_reader.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => { let _ = to_engine_tx.send(buf[..n].to_vec()); }
                Err(_) => return,
            }
        }
    });
    let mut tun_writer = tun;
    std::thread::spawn(move || {
        while let Ok(pkt) = from_engine_rx.recv() {
            if tun_writer.write_all(&pkt).is_err() {
                return;
            }
        }
    });

    // Dial the phone and handshake.
    let mut link = TcpStream::connect(&args.link).unwrap_or_else(|e| {
        eprintln!("nxpump: cannot connect to phone at {}: {e}", args.link);
        std::process::exit(1);
    });
    let hello = client_handshake(&mut link, "nxpump").unwrap_or_else(|e| {
        eprintln!("nxpump: handshake failed: {e}");
        std::process::exit(1);
    });
    println!("handshake ok: phone={} armed={}", hello.phone_name, hello.armed);
    if !hello.armed {
        eprintln!("nxpump: the phone is not armed — enable 'Allow connection' on the phone first");
        std::process::exit(2);
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut byte = [0u8; 1];
            let _ = std::io::stdin().read(&mut byte);
            stop.store(true, Ordering::Relaxed);
        });
    }

    let gateway: Ipv4Address = args.gateway.parse().expect("gateway IP");
    let mut engine = Engine::new(to_engine_rx, from_engine_tx, link, gateway, TrafficCounters::new())
        .expect("engine init");
    println!("engine running");
    match engine.run(stop) {
        Ok(()) => println!("engine stopped"),
        Err(e) => {
            eprintln!("nxpump: engine error: {e}");
            std::process::exit(1);
        }
    }
}
