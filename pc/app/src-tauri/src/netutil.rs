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
}
