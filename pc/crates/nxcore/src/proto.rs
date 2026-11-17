//! NXLP v1 — the NexLink wire protocol.
//!
//! One framed stream carries everything between the PC and the phone, over
//! any transport (USB via ADB forwarding, Wi-Fi, Bluetooth RFCOMM).
//!
//! Frame layout: `u32 BE body_len | u8 type | payload…`
//! where `body_len` counts the type byte plus the payload.

use std::io;

pub const PROTO_VERSION: u16 = 1;
pub const DEFAULT_PORT: u16 = 47777;

pub const T_HELLO: u8 = 0x01;
pub const T_HELLO_ACK: u8 = 0x02;
pub const T_OPEN: u8 = 0x03;
pub const T_OPEN_OK: u8 = 0x04;
pub const T_OPEN_ERR: u8 = 0x05;
pub const T_DATA: u8 = 0x06;
pub const T_CLOSE: u8 = 0x07;
pub const T_PING: u8 = 0x08;
pub const T_PONG: u8 = 0x09;
pub const T_BYE: u8 = 0x0A;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const CLOSE_FIN: u8 = 0x01;
pub const CLOSE_RST: u8 = 0x02;

/// Error code used in OPEN_ERR when the phone's arm switch is off.
pub const ERR_NOT_ARMED: u8 = 1;
pub const ERR_CONNECT_FAILED: u8 = 2;

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Hello { version: u16, name: String },
    HelloAck { armed: bool, name: String },
    Open { flow: u32, proto: u8, ip: [u8; 4], port: u16 },
    OpenOk { flow: u32 },
    OpenErr { flow: u32, code: u8 },
    Data { flow: u32, data: Vec<u8> },
    Close { flow: u32, flags: u8 },
    Ping,
    Pong,
    Bye,
}

impl Frame {
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut body = Vec::with_capacity(64);
        match self {
            Frame::Hello { version, name } => {
                body.push(T_HELLO);
                body.extend_from_slice(&version.to_be_bytes());
                body.extend_from_slice(name.as_bytes());
            }
            Frame::HelloAck { armed, name } => {
                body.push(T_HELLO_ACK);
                body.push(if *armed { 1 } else { 0 });
                body.extend_from_slice(name.as_bytes());
            }
            Frame::Open { flow, proto, ip, port } => {
                body.push(T_OPEN);
                body.extend_from_slice(&flow.to_be_bytes());
                body.push(*proto);
                body.extend_from_slice(ip);
                body.extend_from_slice(&port.to_be_bytes());
            }
            Frame::OpenOk { flow } => {
                body.push(T_OPEN_OK);
                body.extend_from_slice(&flow.to_be_bytes());
            }
            Frame::OpenErr { flow, code } => {
                body.push(T_OPEN_ERR);
                body.extend_from_slice(&flow.to_be_bytes());
                body.push(*code);
            }
            Frame::Data { flow, data } => {
                body.push(T_DATA);
                body.extend_from_slice(&flow.to_be_bytes());
                body.extend_from_slice(data);
            }
            Frame::Close { flow, flags } => {
                body.push(T_CLOSE);
                body.extend_from_slice(&flow.to_be_bytes());
                body.push(*flags);
            }
            Frame::Ping => body.push(T_PING),
            Frame::Pong => body.push(T_PONG),
            Frame::Bye => body.push(T_BYE),
        }
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
    }

    fn decode(body: &[u8]) -> io::Result<Frame> {
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed NXLP frame");
        if body.is_empty() {
            return Err(bad());
        }
        let ty = body[0];
        let p = &body[1..];
        let u32_at = |b: &[u8], i: usize| -> io::Result<u32> {
            b.get(i..i + 4)
                .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
                .ok_or_else(bad)
        };
        let u16_at = |b: &[u8], i: usize| -> io::Result<u16> {
            b.get(i..i + 2)
                .map(|s| u16::from_be_bytes([s[0], s[1]]))
                .ok_or_else(bad)
        };
        Ok(match ty {
            T_HELLO => Frame::Hello {
                version: u16_at(p, 0)?,
                name: String::from_utf8_lossy(&p[2..]).into_owned(),
            },
            T_HELLO_ACK => Frame::HelloAck {
                armed: p.first() == Some(&1),
                name: String::from_utf8_lossy(p.get(1..).unwrap_or(&[])).into_owned(),
            },
            T_OPEN => {
                let mut ip = [0u8; 4];
                ip.copy_from_slice(p.get(5..9).ok_or_else(bad)?);
                Frame::Open { flow: u32_at(p, 0)?, proto: *p.get(4).ok_or_else(bad)?, ip, port: u16_at(p, 9)? }
            }
            T_OPEN_OK => Frame::OpenOk { flow: u32_at(p, 0)? },
            T_OPEN_ERR => Frame::OpenErr { flow: u32_at(p, 0)?, code: *p.get(4).ok_or_else(bad)? },
            T_DATA => Frame::Data { flow: u32_at(p, 0)?, data: p.get(4..).ok_or_else(bad)?.to_vec() },
            T_CLOSE => Frame::Close { flow: u32_at(p, 0)?, flags: *p.get(4).ok_or_else(bad)? },
            T_PING => Frame::Ping,
            T_PONG => Frame::Pong,
            T_BYE => Frame::Bye,
            _ => return Err(bad()),
        })
    }
}

/// Incremental frame parser: feed bytes in, pull whole frames out.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(64 * 1024) }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len == 0 || len > 16 * 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "NXLP frame length out of range"));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let body: Vec<u8> = self.buf.drain(..4 + len).skip(4).collect();
        Ok(Some(Frame::decode(&body)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_frames() {
        let frames = vec![
            Frame::Hello { version: 1, name: "pc".into() },
            Frame::HelloAck { armed: true, name: "phone".into() },
            Frame::Open { flow: 7, proto: PROTO_TCP, ip: [203, 0, 113, 7], port: 443 },
            Frame::OpenOk { flow: 7 },
            Frame::OpenErr { flow: 7, code: ERR_CONNECT_FAILED },
            Frame::Data { flow: 7, data: vec![1, 2, 3, 250] },
            Frame::Close { flow: 7, flags: CLOSE_FIN },
            Frame::Ping,
            Frame::Pong,
            Frame::Bye,
        ];
        let mut wire = Vec::new();
        for f in &frames {
            f.encode(&mut wire);
        }
        let mut r = FrameReader::new();
        // Feed in awkward chunks to prove the parser is incremental.
        for chunk in wire.chunks(3) {
            r.feed(chunk);
        }
        for f in &frames {
            assert_eq!(r.next_frame().unwrap().as_ref(), Some(f));
        }
        assert_eq!(r.next_frame().unwrap(), None);
    }

    #[test]
    fn oversized_frame_length_is_rejected() {
        let mut r = FrameReader::new();
        // A header claiming a 64 MiB body must error, not allocate/wait.
        r.feed(&(64u32 * 1024 * 1024).to_be_bytes());
        assert!(r.next_frame().is_err());
    }

    #[test]
    fn malformed_frames_error_instead_of_panicking() {
        // Unknown type byte.
        let mut r = FrameReader::new();
        r.feed(&[0, 0, 0, 1, 0x7F]);
        assert!(r.next_frame().is_err());
        // OPEN with a truncated payload.
        let mut r = FrameReader::new();
        r.feed(&[0, 0, 0, 3, T_OPEN, 0, 0]);
        assert!(r.next_frame().is_err());
        // Zero-length body.
        let mut r = FrameReader::new();
        r.feed(&[0, 0, 0, 0]);
        assert!(r.next_frame().is_err());
    }
}
