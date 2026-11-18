//! Windows route + DNS management for the tunnel (backlog item 2).
//!
//! While connected, NexLink installs two `/1` routes via the virtual
//! gateway (10.77.0.1) so all PC traffic enters the tunnel without
//! deleting the real default route, plus — on Wi-Fi — a `/32` host route
//! to the phone via the physical gateway, so the link stream itself never
//! enters the tunnel. The adapter's DNS is pointed at the virtual
//! gateway (10.77.0.1) so the phone's DNS interception answers every
//! lookup. Everything is removed / restored on disconnect.
//!
//! All of it goes through the `route` / `netsh` command-line tools
//! (`std::process`) — there is no stable Rust API for this — and both
//! need the app to run elevated; see [`is_elevated`]. Only exit codes
//! are trusted, never the (localized) command output.

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use crate::netutil;
use crate::wintun_backend::{ADAPTER_NAME, GATEWAY_ADDRESS};

/// Run a command, capturing its output; success is the exit code only.
fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("could not run {cmd} ({e})"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let mut msg = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if msg.is_empty() {
            msg = String::from_utf8_lossy(&output.stdout).trim().to_string();
        }
        Err(if msg.is_empty() {
            format!("{cmd} failed")
        } else {
            format!("{cmd} failed: {msg}")
        })
    }
}

/// One route we installed, so disconnect can remove exactly that route.
struct AddedRoute {
    destination: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
}

impl AddedRoute {
    fn add(&self) -> Result<(), String> {
        run(
            "route",
            &[
                "add",
                &self.destination.to_string(),
                "mask",
                &self.mask.to_string(),
                &self.gateway.to_string(),
                "metric",
                "1",
            ],
        )
        .map(|_| ())
    }

    /// Best effort: a missing route is not an error on the way out.
    fn delete(&self) {
        let _ = run(
            "route",
            &[
                "delete",
                &self.destination.to_string(),
                "mask",
                &self.mask.to_string(),
                &self.gateway.to_string(),
            ],
        );
    }
}

/// The routes + DNS change installed by [`install`]. Dropping it does
/// nothing on purpose — removal is always explicit, via [`TunnelRoutes::remove`],
/// so a panic mid-connect cannot silently leave the PC routed nowhere.
pub struct TunnelRoutes {
    routes: Vec<AddedRoute>,
    dns_set: bool,
}

impl TunnelRoutes {
    /// Remove every route installed by [`install`] and restore the
    /// adapter's DNS to DHCP. Best effort throughout: disconnect must
    /// never fail because one route is already gone.
    pub fn remove(self) {
        for route in &self.routes {
            route.delete();
        }
        if self.dns_set {
            let _ = run(
                "netsh",
                &[
                    "interface", "ipv4", "set", "dnsservers",
                    &format!("name={ADAPTER_NAME}"),
                    "source=dhcp",
                ],
            );
        }
    }
}

/// The PC's current default gateway (lowest-metric `0.0.0.0/0` route).
/// Needed for the Wi-Fi `/32` host route: the link to the phone must
/// keep going via the physical network, not the tunnel.
pub fn physical_gateway() -> Result<Ipv4Addr, String> {
    let out = run("route", &["print", "-4"])?;
    netutil::parse_default_gateway(&out).ok_or_else(|| {
        "Could not find the physical default gateway (needed for the Wi-Fi host route). Is this PC connected to a network?".to_string()
    })
}

/// Install the tunnel routes (and adapter DNS). On any failure the
/// routes installed so far are removed again and the error is returned.
pub fn install(transport: &str, phone_ip: Option<Ipv4Addr>) -> Result<TunnelRoutes, String> {
    let mut installed = TunnelRoutes { routes: Vec::new(), dns_set: false };

    // Wi-Fi first: without the /32 host route, the link stream to the
    // phone would itself be routed into the tunnel and deadlock.
    if transport == "wifi" {
        let ip = phone_ip
            .ok_or_else(|| "Wi-Fi connect needs the phone's IP address.".to_string())?;
        let gw = physical_gateway()?;
        let host = AddedRoute {
            destination: ip,
            mask: Ipv4Addr::new(255, 255, 255, 255),
            gateway: gw,
        };
        // A crashed run may have left this route behind; clear it first.
        host.delete();
        host.add().map_err(|e| {
            format!("Could not add the host route to the phone ({ip} via {gw}): {e}")
        })?;
        installed.routes.push(host);
    }

    // The two /1s together cover the whole IPv4 space and beat the
    // default route (longest-prefix match) without deleting it.
    for (destination, mask) in [
        (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)),
        (Ipv4Addr::new(128, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)),
    ] {
        let route = AddedRoute { destination, mask, gateway: GATEWAY_ADDRESS };
        route.delete(); // stale route from a crashed run
        if let Err(e) = route.add() {
            installed.remove();
            return Err(format!(
                "Could not add route {destination}/{mask} via {GATEWAY_ADDRESS}: {e}"
            ));
        }
        installed.routes.push(route);
    }

    // Point the adapter's DNS at the virtual gateway so lookups go
    // through the tunnel and the phone's DNS interception answers them.
    if let Err(e) = run(
        "netsh",
        &[
            "interface", "ipv4", "set", "dnsservers",
            &format!("name={ADAPTER_NAME}"),
            "source=static",
            "address=10.77.0.1",
            "register=primary",
            "validate=no",
        ],
    ) {
        installed.remove();
        return Err(format!("Could not set the adapter DNS to 10.77.0.1: {e}"));
    }
    installed.dns_set = true;

    Ok(installed)
}

/// Is this process elevated? `net session` only succeeds as admin.
/// Used for a clear error up front instead of a cryptic `route` failure.
pub fn is_elevated() -> bool {
    Command::new("net")
        .args(["session"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
