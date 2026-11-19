//! Small network helpers for the tray app.
//!
//! Pure functions only, so they are unit-tested on every platform —
//! including this Linux VM, where the Windows-only route code itself
//! cannot run (see `routes.rs`).

use std::net::Ipv4Addr;

/// Parse the output of Windows' `route print -4` and return the gateway
/// of the default route (`0.0.0.0/0`) with the lowest metric.
///
/// The table's data rows look like:
/// ```text
///           0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100     25
/// ```
/// (destination, netmask, gateway, interface, metric). Header lines,
/// section titles and "On-link" gateways never match, so localized
/// Windows builds parse the same way — only the numbers matter.
pub fn parse_default_gateway(route_print_stdout: &str) -> Option<Ipv4Addr> {
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in route_print_stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        if fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
            continue;
        }
        let Ok(gateway) = fields[2].parse::<Ipv4Addr>() else {
            continue; // e.g. "On-link"
        };
        let Ok(metric) = fields[4].parse::<u32>() else {
            continue;
        };
        if best.as_ref().is_none_or(|(m, _)| metric < *m) {
            best = Some((metric, gateway));
        }
    }
    best.map(|(_, gateway)| gateway)
}

/// One row of the IPv4 route table as printed by `route print -4`.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteRow {
    pub destination: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// `None` for "On-link" rows.
    pub gateway: Option<Ipv4Addr>,
    pub interface: Ipv4Addr,
    pub metric: u32,
}

/// Parse every data row of `route print -4` output. Same shape as
/// [`parse_default_gateway`]: only the numbers matter, so localized
/// Windows builds parse identically.
pub fn parse_route_table(route_print_stdout: &str) -> Vec<RouteRow> {
    let mut rows = Vec::new();
    for line in route_print_stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let (Ok(destination), Ok(mask), Ok(interface), Ok(metric)) = (
            fields[0].parse::<Ipv4Addr>(),
            fields[1].parse::<Ipv4Addr>(),
            fields[3].parse::<Ipv4Addr>(),
            fields[4].parse::<u32>(),
        ) else {
            continue; // headers, separators, "Persistent Routes:" etc.
        };
        rows.push(RouteRow {
            destination,
            mask,
            gateway: fields[2].parse::<Ipv4Addr>().ok(),
            interface,
            metric,
        });
    }
    rows
}

/// Is there a route `destination`/`mask` via `gateway` bound to the
/// interface whose address is `interface`? This is the read-back check
/// that proves a route we added actually landed on our adapter —
/// `route add` exiting 0 alone never proved that (v0.2.1 trusted it
/// blind and shipped a silent no-traffic build).
pub fn route_bound_to(
    rows: &[RouteRow],
    destination: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
    interface: Ipv4Addr,
) -> bool {
    rows.iter().any(|r| {
        r.destination == destination
            && r.mask == mask
            && r.gateway == Some(gateway)
            && r.interface == interface
    })
}

/// Parse the output of `netsh interface ipv4 show interfaces` and
/// return the interface index (the `if` argument for `route add`) of
/// the interface named `name`.
///
/// Rows look like:
/// ```text
///  12          25        1400  connected    NexLink
/// ```
/// The name is the trailing column and may itself contain spaces, so a
/// row matches when its trimmed end is exactly the name (preceded by
/// whitespace) and its first field parses as the index. The state word
/// is localized on some builds; it is never inspected.
pub fn parse_interface_index(show_interfaces_stdout: &str, name: &str) -> Option<u32> {
    for line in show_interfaces_stdout.lines() {
        let trimmed = line.trim_end();
        if !trimmed.ends_with(name) {
            continue;
        }
        let before = &trimmed[..trimmed.len() - name.len()];
        if !before.ends_with(char::is_whitespace) {
            continue; // the name is only a suffix of a longer name
        }
        match before.split_whitespace().next().and_then(|f| f.parse::<u32>().ok()) {
            Some(idx) => return Some(idx),
            None => continue,
        }
    }
    None
}

/// Does `netsh interface ipv4 show dnsservers` output list `server`
/// as one of the adapter's DNS servers? The labels are localized; the
/// addresses are not, so a whole-token match on the address is enough.
pub fn dns_server_listed(show_dnsservers_stdout: &str, server: Ipv4Addr) -> bool {
    let needle = server.to_string();
    show_dnsservers_stdout.split_whitespace().any(|tok| tok == needle)
}

/// Does `adb forward --list` output contain our forward? Lines look
/// like `<serial> tcp:47777 tcp:47777` (serial, local, remote).
pub fn adb_forward_present(forward_list_stdout: &str, port: u16) -> bool {
    let spec = format!("tcp:{port}");
    forward_list_stdout.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.len() >= 3 && fields[1] == spec && fields[2] == spec
    })
}

/// Parse the output of Windows' `reg query HKCU\...\Run /v <name>` and
/// return the value's data (the command Windows runs at logon), if the
/// value exists.
///
/// A value line looks like:
/// ```text
///     NexLink    REG_SZ    "C:\Program Files\NexLink\NexLink.exe"
/// ```
/// The header line (`HKEY_CURRENT_USER\...`) and the trailing blank line
/// never match. `REG_SZ`/`REG_EXPAND_SZ` are not localized, so this
/// parses the same on every Windows language. The data may itself
/// contain spaces (it is the quoted exe path), so everything after the
/// type token is the data — it is returned untrimmed of its quotes on
/// purpose; callers compare it against the quoted current exe path.
pub fn parse_reg_query_value(reg_query_stdout: &str, name: &str) -> Option<String> {
    for line in reg_query_stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 || fields[0] != name {
            continue;
        }
        if fields[1] != "REG_SZ" && fields[1] != "REG_EXPAND_SZ" {
            continue;
        }
        // The data is everything after the type token, spaces included:
        // find the type token in the original line and take the rest.
        let after_type = line.split(fields[1]).nth(1)?;
        let data = after_type.trim();
        if data.is_empty() {
            continue;
        }
        return Some(data.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r"===========================================================================
Interface List
  7...aa bb cc dd ee ff ......Intel(R) Wi-Fi 6
  1...........................Software Loopback Interface 1
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100     25
          0.0.0.0          0.0.0.0       10.77.0.1      10.77.0.2      1
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link     192.168.1.100    281
===========================================================================
Persistent Routes:
  None
";

    #[test]
    fn picks_lowest_metric_default() {
        // The 10.77.0.1 row is a /1-route artefact of a stale tunnel, not
        // a real default route — but it IS a 0.0.0.0/0 row with the lowest
        // metric, so the parser must return it. (In practice install()
        // runs before any NexLink route exists, so this row is absent.)
        assert_eq!(
            parse_default_gateway(SAMPLE),
            Some(Ipv4Addr::new(10, 77, 0, 1))
        );
    }

    #[test]
    fn single_default_route() {
        let out = "          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100     25\n";
        assert_eq!(
            parse_default_gateway(out),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn no_default_route() {
        let out = "        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\n";
        assert_eq!(parse_default_gateway(out), None);
    }

    #[test]
    fn ignores_on_link_and_headers() {
        let out = "Network Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0         On-link      10.0.0.5     10\n";
        assert_eq!(parse_default_gateway(out), None);
    }

    const REG_QUERY_SAMPLE: &str = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n    NexLink    REG_SZ    \"C:\\Program Files\\NexLink\\NexLink.exe\"\r\n    OtherApp    REG_SZ    C:\\Tools\\other.exe\r\n\r\n";

    #[test]
    fn reg_query_finds_value_with_spaces() {
        assert_eq!(
            parse_reg_query_value(REG_QUERY_SAMPLE, "NexLink"),
            Some("\"C:\\Program Files\\NexLink\\NexLink.exe\"".to_string())
        );
    }

    #[test]
    fn reg_query_other_value() {
        assert_eq!(
            parse_reg_query_value(REG_QUERY_SAMPLE, "OtherApp"),
            Some("C:\\Tools\\other.exe".to_string())
        );
    }

    #[test]
    fn reg_query_missing_value() {
        assert_eq!(parse_reg_query_value(REG_QUERY_SAMPLE, "Nope"), None);
    }

    #[test]
    fn reg_query_empty_output() {
        assert_eq!(parse_reg_query_value("", "NexLink"), None);
    }

    const ROUTES_WITH_TUNNEL: &str = r"===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0        128.0.0.0        10.77.0.1       10.77.0.2       1
        128.0.0.0        128.0.0.0        10.77.0.1       10.77.0.2       1
          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.100      25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1     331
===========================================================================
Persistent Routes:
  None
";

    #[test]
    fn route_table_parses_rows() {
        let rows = parse_route_table(ROUTES_WITH_TUNNEL);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].gateway, Some(Ipv4Addr::new(10, 77, 0, 1)));
        assert_eq!(rows[3].gateway, None); // On-link
    }

    #[test]
    fn route_bound_to_finds_tunnel_routes() {
        let rows = parse_route_table(ROUTES_WITH_TUNNEL);
        let mask = Ipv4Addr::new(128, 0, 0, 0);
        let gw = Ipv4Addr::new(10, 77, 0, 1);
        let iface = Ipv4Addr::new(10, 77, 0, 2);
        assert!(route_bound_to(&rows, Ipv4Addr::new(0, 0, 0, 0), mask, gw, iface));
        assert!(route_bound_to(&rows, Ipv4Addr::new(128, 0, 0, 0), mask, gw, iface));
        // Same gateway, wrong interface (the v0.2.1 blind spot).
        assert!(!route_bound_to(
            &rows,
            Ipv4Addr::new(0, 0, 0, 0),
            mask,
            gw,
            Ipv4Addr::new(192, 168, 1, 100)
        ));
        // Route missing entirely.
        assert!(!route_bound_to(
            &rows,
            Ipv4Addr::new(64, 0, 0, 0),
            mask,
            gw,
            iface
        ));
    }

    const INTERFACES: &str = r"Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
  1          75  4294967295  connected    Loopback Pseudo-Interface 1
 12          25        1400  connected    NexLink
  9          35        1500  disconnected Wi-Fi
";

    #[test]
    fn interface_index_found() {
        assert_eq!(parse_interface_index(INTERFACES, "NexLink"), Some(12));
        assert_eq!(parse_interface_index(INTERFACES, "Wi-Fi"), Some(9));
        assert_eq!(parse_interface_index(INTERFACES, "Ethernet"), None);
    }

    #[test]
    fn interface_index_rejects_suffix_names() {
        let out = "  5          25        1400  connected    NotNexLink\n";
        assert_eq!(parse_interface_index(out, "NexLink"), None);
    }

    #[test]
    fn dns_server_listing() {
        let out = "Configuration for interface \"NexLink\"\n    Statically Configured DNS Servers:    10.77.0.1\n                                          None\n";
        assert!(dns_server_listed(out, Ipv4Addr::new(10, 77, 0, 1)));
        assert!(!dns_server_listed(out, Ipv4Addr::new(10, 77, 0, 2)));
        let dhcp = "Configuration for interface \"NexLink\"\n    DNS servers configured through DHCP:  192.168.1.1\n";
        assert!(!dns_server_listed(dhcp, Ipv4Addr::new(10, 77, 0, 1)));
    }

    #[test]
    fn adb_forward_listing() {
        let out = "emulator-5554 tcp:47777 tcp:47777\n";
        assert!(adb_forward_present(out, 47777));
        assert!(!adb_forward_present(out, 47778));
        assert!(!adb_forward_present("", 47777));
        assert!(!adb_forward_present("emulator-5554 tcp:47777 tcp:5555\n", 47777));
    }
}
