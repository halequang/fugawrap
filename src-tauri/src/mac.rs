//! macOS helpers: run `networksetup` and find network services.
//!
//! Proxy and DNS settings are per network service (Wi-Fi, Ethernet, ...), not
//! global. `networksetup` often exits 0 on errors and prints them instead, so its
//! output is checked too.

use std::process::Command;

const NETWORKSETUP: &str = "/usr/sbin/networksetup";

pub fn networksetup(args: &[&str]) -> Result<String, String> {
    let out = Command::new(NETWORKSETUP)
        .args(args)
        .output()
        .map_err(|e| format!("Could not run networksetup: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let failed = !out.status.success()
        || [&stdout, &stderr].iter().any(|t| {
            t.contains("** Error") || t.contains("not a recognized network service") || t.contains("requires admin")
        });
    if failed {
        let msg = if stderr.is_empty() { stdout } else { stderr };
        return Err(format!("networksetup {}: {msg}", args.first().unwrap_or(&"")));
    }
    Ok(stdout)
}

/// Enabled network services, in the user's service order.
pub fn enabled_services() -> Result<Vec<String>, String> {
    let out = networksetup(&["-listallnetworkservices"])?;
    Ok(parse_service_list(&out))
}

fn parse_service_list(out: &str) -> Vec<String> {
    out.lines()
        .skip(1) // "An asterisk (*) denotes that a network service is disabled."
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

/// The network service that owns the default route, e.g. "Wi-Fi".
pub fn active_service() -> Option<String> {
    let route = Command::new("/sbin/route").args(["-n", "get", "default"]).output().ok()?;
    let route = String::from_utf8_lossy(&route.stdout);
    let device = route.lines().find_map(|l| l.trim().strip_prefix("interface:"))?.trim().to_string();
    let order = networksetup(&["-listnetworkserviceorder"]).ok()?;
    service_for_device(&order, &device)
}

/// Find the service for a device in `-listnetworkserviceorder` output:
/// "(3) Wi-Fi" followed by "(Hardware Port: Wi-Fi, Device: en0)".
fn service_for_device(order: &str, device: &str) -> Option<String> {
    let mut name: Option<&str> = None;
    for line in order.lines().map(str::trim) {
        if let Some(port) = line.strip_prefix("(Hardware Port:") {
            let dev = port.rsplit_once("Device:").map(|(_, d)| d.trim_end_matches(')').trim());
            if dev == Some(device) {
                return name.map(str::to_string);
            }
        } else if line.starts_with('(') {
            // "(3) Wi-Fi"; a disabled service shows "(*) Wi-Fi" and is skipped.
            name = line.split_once(") ").filter(|(n, _)| *n != "(*").map(|(_, s)| s);
        }
    }
    None
}

/// Quote for a POSIX shell.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Run a shell command as root through the macOS administrator password prompt.
pub fn run_as_admin(command: &str) -> Result<(), String> {
    let escaped = command.replace('\\', r"\\").replace('"', "\\\"");
    let script = format!("do shell script \"{escaped}\" with administrator privileges");
    let out = Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("Could not run osascript: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("-128") {
        return Err("Administrator permission was declined".into());
    }
    Err(err.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_service_for_a_device() {
        let order = "An asterisk (*) denotes that a network service is disabled.
(1) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(*) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(3) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(4) OpenVPN UDP
(Hardware Port: com.atrix.rusvpn, Device: )";
        assert_eq!(service_for_device(order, "en0").as_deref(), Some("Wi-Fi"));
        assert_eq!(service_for_device(order, "en7").as_deref(), Some("USB 10/100/1000 LAN"));
        assert_eq!(service_for_device(order, "bridge0"), None);
        assert_eq!(service_for_device(order, "utun3"), None);
    }

    #[test]
    fn lists_enabled_services_only() {
        let out = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB LAN";
        assert_eq!(parse_service_list(out), ["Wi-Fi", "USB LAN"]);
    }

    #[test]
    fn quotes_for_the_shell() {
        assert_eq!(sh_quote("Bob's Wi-Fi"), r"'Bob'\''s Wi-Fi'");
    }
}
