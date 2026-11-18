# resources/

This directory holds `wintun.dll` (the WinTun driver library, amd64) at
build time. It is **not committed** — CI downloads it from the official
release and verifies the SHA-256 (see `.github/workflows/build.yml`).

For a local `cargo tauri build` on Windows, fetch it the same way:

```powershell
Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile "$env:TEMP\wintun-0.14.1.zip"
# Verify: (Get-FileHash "$env:TEMP\wintun-0.14.1.zip" -Algorithm SHA256).Hash
# must be 07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51
Expand-Archive "$env:TEMP\wintun-0.14.1.zip" -DestinationPath "$env:TEMP\wintun"
Copy-Item "$env:TEMP\wintun\wintun\bin\amd64\wintun.dll" .
```

The installer bundles it as a Tauri resource (`resources/wintun.dll`
next to the exe); the app also accepts the DLL sitting directly next to
the exe (see `src/wintun_backend.rs`).
