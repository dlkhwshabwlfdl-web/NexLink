# NexLink — Architecture

NexLink shares a phone's internet connection with a Windows PC — **including
whatever VPN, DNS configuration, or proxy the phone itself is using** — over
USB (primary), Wi-Fi, or Bluetooth. It is built the way PdaNet+ works, not the
way "net share" apps work:

- **No proxy, ever.** NexLink never touches the Windows proxy settings. The PC
  gets a real (virtual) network adapter, so every app on the PC — browsers,
  games, launchers, anything — uses the connection like any other network.
- **The phone is the gateway.** Traffic is not NAT-ed by the phone's OS
  tethering (which bypasses the phone's VPN and can be blocked by carriers).
  Instead, the phone app re-originates every connection with its own sockets,
  so traffic leaves the phone exactly the way the phone app's own traffic
  does: through the phone's VPN tunnel, with the phone's DNS, end to end.

## Components

```
┌─ Windows PC ────────────────────────────────┐        ┌─ Android phone ──────────────┐
│  any app                                     │        │  NexLink app                  │
│     │ IP packets                             │        │   ├─ listeners (USB/Wi-Fi/BT) │
│  Wintun adapter ──► nxcore stack (smoltcp)   │  NXLP  │   ├─ flow relay (sockets)     │
│     terminates TCP/UDP, opens "flows" ───────┼───────►│   └─ DNS interception         │
│  NexLink tray app (Tauri)                    │  link  │        │ phone sockets        │
│   Connect button, settings, status           │        │        ▼                      │
└──────────────────────────────────────────────┘        │  phone network / phone VPN    │
                                                         └───────────────────────────────┘
```

### 1. PC core — `pc/crates/nxcore` (Rust)

- Owns a **Wintun** adapter on Windows (a real TUN device; on Linux a
  `/dev/net/tun` device is used for development and testing).
- A user-space TCP/IP stack (**smoltcp**) impersonates every destination:
  when a PC app opens a connection, the stack completes the handshake locally
  and translates the byte stream into a NexLink **flow**.
- On *Connect*, the core installs routes (`0.0.0.0/1` + `128.0.0.0/1` via the
  adapter, which overrides the default route without deleting it) and points
  the adapter's DNS at the virtual gateway. On *Disconnect* everything is
  restored. For Wi-Fi transport a `/32` host route to the phone via the
  original gateway is added first, so the link itself never enters the tunnel.
- USB transport uses **ADB forwarding** (the same requirement as PdaNet+:
  USB debugging enabled once on the phone). The PC core bundles `adb`,
  forwards a local port to the phone app's listener, and dials it.
- Wi-Fi transport dials the phone's IP directly. Bluetooth uses an RFCOMM
  stream. All three carry the identical wire protocol.

### 2. Wire protocol — NXLP v1

One framed stream per link. Frame = `u32 BE length | u8 type | payload`.

| Type | Name      | Payload |
|------|-----------|---------|
| 0x01 | HELLO     | protocol version, client name (PC → phone) |
| 0x02 | HELLO_ACK | `armed` flag, phone name (phone → PC) |
| 0x03 | OPEN      | flow id, proto (6=TCP, 17=UDP), dest IP, dest port |
| 0x04 | OPEN_OK   | flow id |
| 0x05 | OPEN_ERR  | flow id, error code |
| 0x06 | DATA      | flow id, raw bytes |
| 0x07 | CLOSE     | flow id, flags (FIN / RST) |
| 0x08 | PING      | keepalive (20 s) |
| 0x09 | PONG      | keepalive reply |
| 0x0A | BYE       | clean shutdown |

Because each flow's TCP connection is *terminated* on the phone and the link
itself is a short local stream, there is no TCP-over-TCP meltdown; overhead is
a few bytes of framing per chunk.

### 3. Phone app — `android/` (Kotlin, no third-party UI libraries)

- A foreground service runs the listeners:
  - TCP on `127.0.0.1:47777` — reached from the PC through `adb forward` (USB).
  - TCP on the LAN address, same port — Wi-Fi transport.
  - Bluetooth RFCOMM with the NexLink service UUID — Bluetooth transport.
- **Flow relay:** for every OPEN frame the app dials a real Android socket to
  the destination and copies bytes both ways. UDP flows are associations with
  one `DatagramSocket` each.
- **DNS interception:** UDP flows to port 53 are *not* relayed to the dialed
  address; the query is resolved with the phone's own resolver
  (`Network.getAllByName` / the active network's DNS) and the answer is
  returned as if it came from the dialed server. This guarantees the PC uses
  the phone's (VPN's) DNS, not whatever the PC had configured.
- **The arm switch (product rule):** the app has one big switch,
  *"Allow PC connection"*. It can only be switched **on** while at least one
  transport is physically present (USB attached, Bluetooth on, or Wi-Fi
  connected). Switching it on starts the foreground service and its
  listeners; switching it off stops everything. The phone never initiates
  anything and never auto-connects. If the PC presses *Connect* while the
  phone is not armed, there is no listener to answer (or the handshake
  reports `armed = false`), and the PC shows
  *"Enable 'Allow connection' on your phone first."*

### 4. PC app — `pc/app` (Tauri, tray-only)

- Lives in the Windows notification area (the "Show hidden icons" tray).
  No main window; a small settings window opens from the tray menu.
- Tray menu: **Connect / Disconnect**, status line, transport selector
  (USB / Wi-Fi / Bluetooth), phone address (Wi-Fi), start-with-Windows
  toggle, Exit.
- **Manual connect only (product rule):** the app never retries in a loop.
  Connect is a button press; a failed attempt reports once and stops.
- **Verified connect (v0.3.0):** "Connected" is gated on end-to-end probes
  through the tunnel itself — a DNS query answered via the phone's
  interception, then a TCP open the phone completes — with named failure
  stages ("DNS check failed", "Traffic check failed"). The /1 routes are
  bound to the adapter's interface index and read back from the live route
  table after install; the adapter's DNS is read back too. The status line
  shows live byte counters, a USB tunnel's `adb forward` is supervised for
  its whole life, and every run logs to `%APPDATA%/NexLink/nexlink.log`.
  The whole data path shares one MTU (`nxcore::LINK_MTU`, 1400) — the
  v0.2.1 engine/adapter MTU split (1500 vs 1400) silently dropped all bulk
  traffic while reporting "Connected", which is what these gates exist to
  make impossible.
- Creating the adapter and changing routes needs elevation; the app asks for
  UAC once when connecting.

## Addressing

| Role | Address |
|------|---------|
| Virtual gateway (the stack) | `10.77.0.1` |
| PC adapter | `10.77.0.2/24` |
| Phone listener | port `47777` (all transports) |

## Known limits of v1

- No ICMP relay: `ping` from the PC won't cross (TCP/UDP only — the same
  trade-off most tethering tools make).
- One link stream carries all flows; a single huge download can add latency
  to other flows (head-of-line). Per-flow credit windows are planned.
- Bluetooth transport: phone listener implemented; PC-side RFCOMM dialer is
  the last piece scheduled.

## Why not standard USB tethering / hotspot?

Both are done by the phone's OS *below* the VPN: tethered traffic leaves the
phone outside the VPN tunnel, with the carrier's DNS, and carriers can detect
and throttle it. NexLink exists specifically to avoid that path.
