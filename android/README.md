# NexLink for Android

The phone half of NexLink: a small companion app that re-originates the
PC's connections with its own sockets, so the PC inherits the phone's
network exactly — including the phone's **VPN and DNS**.

## Using it

1. Install the APK (from the GitHub Actions build or a release).
2. Connect at least one transport: a USB cable, Bluetooth, or Wi-Fi.
   - For **USB**, enable **USB debugging** once (Settings → Developer
     options) — the PC side talks to the app through ADB forwarding, the
     same requirement PdaNet+ has.
3. Open NexLink and turn on **“Allow PC connection”**. The switch only
   unlocks while a transport is actually connected.
4. On the PC, press **Connect** in the NexLink tray app.

Nothing ever connects on its own: the phone only listens while the switch
is on, and the PC only connects when you press the button.

## Notes

- **VPN split tunneling:** if your VPN app excludes NexLink from the
  tunnel (split-tunnel / per-app settings), the PC's traffic bypasses the
  VPN too. Include NexLink in the VPN to have the PC fully covered.
- The app uses **no third-party libraries** — Android framework only.

## Building

CI builds the APK (see `.github/workflows/build.yml`). Locally, with the
Android SDK installed:

```bash
gradle :app:assembleDebug   # or open this folder in Android Studio
```
