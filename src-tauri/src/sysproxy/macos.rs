//! macOS: the HTTP and HTTPS proxy of every enabled network service, set with
//! `networksetup`. Admin users can change these without a password prompt.

use crate::mac::{enabled_services, networksetup};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Service {
    pub name: String,
    pub web: Proxy,
    pub secure: Proxy,
    pub bypass: Vec<String>,
    pub auto_url: Option<String>,
    pub auto_enabled: bool,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub services: Vec<Service>,
}

/// Parse "Enabled: Yes / Server: x / Port: n" and "URL: x / Enabled: No" output.
fn field<'a>(out: &'a str, name: &str) -> &'a str {
    out.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(':')).map(str::trim).unwrap_or("")
}

fn parse_proxy(out: &str) -> Proxy {
    Proxy {
        enabled: field(out, "Enabled") == "Yes",
        server: field(out, "Server").to_string(),
        port: field(out, "Port").parse().unwrap_or(0),
    }
}

fn parse_bypass(out: &str) -> Vec<String> {
    if out.starts_with("There aren't any") {
        return Vec::new();
    }
    out.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect()
}

fn read_service(name: &str) -> Result<Service, String> {
    let auto = networksetup(&["-getautoproxyurl", name])?;
    let url = field(&auto, "URL");
    Ok(Service {
        name: name.to_string(),
        web: parse_proxy(&networksetup(&["-getwebproxy", name])?),
        secure: parse_proxy(&networksetup(&["-getsecurewebproxy", name])?),
        bypass: parse_bypass(&networksetup(&["-getproxybypassdomains", name])?),
        auto_url: (!url.is_empty() && url != "(null)").then(|| url.to_string()),
        auto_enabled: field(&auto, "Enabled") == "Yes",
    })
}

pub fn read() -> Result<Snapshot, String> {
    // Services without a device (some VPNs) can't be read; skip them.
    let services: Vec<Service> = enabled_services()?.iter().filter_map(|n| read_service(n).ok()).collect();
    if services.is_empty() {
        return Err("No active network adapter found".into());
    }
    Ok(Snapshot { services })
}

fn set_proxy(kind: &str, service: &str, p: &Proxy) -> Result<(), String> {
    if !p.server.is_empty() && p.port != 0 {
        // Setting the server also turns the proxy on, so set the state afterwards.
        networksetup(&[&format!("-set{kind}"), service, &p.server, &p.port.to_string()])?;
    }
    networksetup(&[&format!("-set{kind}state"), service, if p.enabled { "on" } else { "off" }])?;
    Ok(())
}

fn write_service(s: &Service) -> Result<(), String> {
    set_proxy("webproxy", &s.name, &s.web)?;
    set_proxy("securewebproxy", &s.name, &s.secure)?;
    let mut args = vec!["-setproxybypassdomains", s.name.as_str()];
    if s.bypass.is_empty() {
        args.push("Empty");
    } else {
        args.extend(s.bypass.iter().map(String::as_str));
    }
    networksetup(&args)?;
    if let Some(url) = &s.auto_url {
        networksetup(&["-setautoproxyurl", &s.name, url])?;
    }
    networksetup(&["-setautoproxystate", &s.name, if s.auto_enabled { "on" } else { "off" }])?;
    Ok(())
}

/// Write every service; fails only when none could be written, so one odd
/// service (a VPN without a device) doesn't block the rest.
pub fn write(s: &Snapshot) -> Result<(), String> {
    let mut first_err = None;
    let mut ok = false;
    for service in &s.services {
        match write_service(service) {
            Ok(()) => ok = true,
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    match (ok, first_err) {
        (false, Some(e)) => Err(format!("Could not change the system proxy: {e}")),
        _ => Ok(()),
    }
}

const LOCAL: [&str; 6] = ["*.local", "169.254/16", "localhost", "127.0.0.1", "10.0.0.0/8", "192.168.0.0/16"];

fn local_proxy(port: u16) -> Proxy {
    Proxy { enabled: true, server: "127.0.0.1".into(), port }
}

pub fn ours(port: u16, now: &Snapshot) -> Snapshot {
    let services = now
        .services
        .iter()
        .map(|s| {
            let mut bypass = s.bypass.clone();
            for l in LOCAL {
                if !bypass.iter().any(|b| b == l) {
                    bypass.push(l.to_string());
                }
            }
            Service {
                name: s.name.clone(),
                web: local_proxy(port),
                secure: local_proxy(port),
                bypass,
                // A PAC script would take precedence over our proxy.
                auto_url: s.auto_url.clone(),
                auto_enabled: false,
            }
        })
        .collect();
    Snapshot { services }
}

fn is_ours(p: &Proxy, port: u16) -> bool {
    p.enabled && p.server == "127.0.0.1" && p.port == port
}

pub fn points_at(s: &Snapshot, port: u16) -> bool {
    s.services.iter().any(|s| is_ours(&s.web, port) || is_ours(&s.secure, port))
}

pub fn turned_off(mut now: Snapshot, port: u16) -> Snapshot {
    for s in &mut now.services {
        for p in [&mut s.web, &mut s.secure] {
            if is_ours(p, port) {
                p.enabled = false;
            }
        }
    }
    now
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_networksetup_output() {
        let p = parse_proxy("Enabled: Yes\nServer: 127.0.0.1\nPort: 18787\nAuthenticated Proxy Enabled: 0");
        assert_eq!(p, local_proxy(18787));
        assert_eq!(parse_proxy("Enabled: No\nServer: \nPort: 0"), Proxy::default());
        assert_eq!(parse_bypass("There aren't any bypass domains set on Wi-Fi."), Vec::<String>::new());
        assert_eq!(parse_bypass("*.local\n169.254/16"), ["*.local", "169.254/16"]);
        assert_eq!(field("URL: (null)\nEnabled: No", "URL"), "(null)");
    }

    #[test]
    fn ours_and_turned_off() {
        let before = Snapshot {
            services: vec![Service { name: "Wi-Fi".into(), bypass: vec!["*.local".into()], auto_enabled: true, ..Default::default() }],
        };
        let on = ours(18787, &before);
        assert!(points_at(&on, 18787));
        assert!(!points_at(&on, 1));
        assert!(!on.services[0].auto_enabled);
        assert_eq!(on.services[0].bypass.iter().filter(|b| *b == "*.local").count(), 1);
        assert!(!points_at(&turned_off(on, 18787), 18787));
    }
}

#[cfg(test)]
mod live {
    /// Reads (never writes) this Mac's settings: `cargo test -- --ignored live_`.
    #[test]
    #[ignore]
    fn live_read_proxy_and_dns() {
        let snap = super::read().unwrap();
        println!("{snap:#?}");
        println!("{}", serde_json::to_string_pretty(&crate::dnsmode::status()).unwrap());
    }
}
