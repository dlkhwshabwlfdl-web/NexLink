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
}
