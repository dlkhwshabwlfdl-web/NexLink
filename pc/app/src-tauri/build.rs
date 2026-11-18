fn main() {
    // On Windows, embed our own application manifest (see
    // windows-app-manifest.xml): `requireAdministrator`, so the installed
    // app elevates itself via UAC instead of needing "Run as
    // administrator" every launch. tauri-build documents this exact
    // pattern (WindowsAttributes::app_manifest); its default manifest
    // is the same file minus the trustInfo block.
    //
    // The build script compiles for the HOST, so `cfg(windows)` here
    // means "built on Windows" — on the Linux cross-check this branch
    // is skipped and the plain build runs instead.
    #[cfg(windows)]
    {
        let attributes = tauri_build::Attributes::new().windows_attributes(
            tauri_build::WindowsAttributes::new()
                .app_manifest(include_str!("windows-app-manifest.xml")),
        );
        tauri_build::try_build(attributes).expect("failed to run tauri-build");
    }
    #[cfg(not(windows))]
    tauri_build::build()
}
