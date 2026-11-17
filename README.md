<p align="center">
  <img src="assets/nexlink-logo-256.png" alt="NexLink logo" width="128" />
</p>

# NexLink

**Share your phone's internet with your PC — VPN, DNS and all — over USB, Wi-Fi or Bluetooth.**

Standard tethering and hotspot route your PC's traffic *around* your phone's
VPN. NexLink doesn't: the phone app re-originates every connection with its
own sockets, so your PC traffic exits through the phone's VPN tunnel and the
phone's DNS, exactly like the phone's own apps.

And unlike proxy-based tools, NexLink installs a **real virtual network
adapter** (Wintun) on Windows. No proxy settings are ever touched, so every
app on the PC just works.

## The rules it is built on

- 🔌 **USB first** (via ADB forwarding, like PdaNet+), Wi-Fi and Bluetooth after.
- 🛡️ **VPN & DNS ride along** — guaranteed by design, not by a settings toggle.
- 🚫 **No proxy.** Not on the PC, not anywhere.
- 🖱️ **Manual connect.** One Connect button in the system tray. No auto-retry loops.
- 📱 **The phone decides.** A small Android companion app has an
  *"Allow connection"* switch that can only be armed while USB / Bluetooth /
  Wi-Fi is actually connected. Nothing connects until both sides say so.
- 🪶 **Tiny footprint.** The PC side lives in the notification tray
  ("Show hidden icons") with one small settings window. That's it.

## How it works

```
PC app ──► Wintun adapter ──► user-space TCP/IP stack ──► flows ══USB/Wi-Fi/BT══► phone app ──► phone sockets ──► phone network / VPN
```

Full design: [ARCHITECTURE.md](ARCHITECTURE.md)

## Status

🚧 **In development.** The core data path (virtual adapter → stack → wire
protocol → phone-side relay) is implemented and covered by an end-to-end
test with a simulated phone. Windows tray app and Android app are in
progress; see the roadmap in [ARCHITECTURE.md](ARCHITECTURE.md).

## Repository layout

| Path | What |
|------|------|
| `pc/crates/nxcore` | Wire protocol, user-space stack, relay engine (Rust) |
| `pc/crates/nxpump` | CLI harness that binds the engine to a TUN/Wintun device |
| `pc/crates/simphone` | A simulated phone relay, used by the end-to-end test |
| `pc/app` | Windows tray app (Tauri) |
| `android` | Android companion app (Kotlin) |

## License

MIT — see [LICENSE](LICENSE).
