//! macOS: set the DNS servers of the network service that owns the default route
//! with `networksetup`. Admin users can usually do this directly; otherwise the
//! change runs through the administrator password prompt.
//!
//! macOS only turns on DNS-over-HTTPS through configuration profiles, so this sets
//! plain DNS. The original servers are saved so Undo can put them back.

use super::{DnsStatus, PROVIDERS};
use crate::mac::{active_service, networksetup, run_as_admin, sh_quote};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::PathBuf;

fn servers_of(provider: &str) -> &'static [&'static str] {
    match provider {
        "google" => &["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
        "opendns" => &["208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53"],
        "adguard" => &["94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        "alibaba" => &["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
        "cloudflare" => &["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
        _ => &[],
    }
}

#[derive(Serialize, Deserialize)]
struct State {
    name: String,
    dns: Vec<String>,
    provider: String,
}

fn state_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library/Application Support/shop.fungamingvn.fugawrap/dns-state.json")
}

fn read_state() -> Option<State> {
    serde_json::from_str(&std::fs::read_to_string(state_path()).ok()?).ok()
}

fn save_state(s: &State) -> Result<(), String> {
    let path = state_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| format!("Could not save DNS state: {e}"))
}

/// Servers set by hand on a service; empty means it uses the network's (DHCP) DNS.
fn servers(service: &str) -> Vec<String> {
    networksetup(&["-getdnsservers", service])
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| l.parse::<IpAddr>().is_ok())
        .map(String::from)
        .collect()
}

fn adapter_json(service: &str) -> Value {
    json!({ "name": service, "servers": servers(service) })
}

pub fn status() -> DnsStatus {
    let state = read_state();
    DnsStatus {
        active: state.is_some(),
        provider: state.as_ref().map(|s| s.provider.clone()),
        original: state.as_ref().map(|s| json!(s.dns)),
        adapter: active_service().map(|s| adapter_json(&s)),
        log: None,
    }
}

/// Set a service's DNS servers ("Empty" for automatic). Tries without a password
/// first and asks for administrator permission only if that is refused.
fn set_servers(service: &str, servers: &[String]) -> Result<(), String> {
    // Only IP addresses ever reach the command line.
    let mut list: Vec<String> = servers.iter().filter(|s| s.parse::<IpAddr>().is_ok()).cloned().collect();
    if list.is_empty() {
        list.push("Empty".into());
    }
    let mut args = vec!["-setdnsservers", service];
    args.extend(list.iter().map(String::as_str));
    if networksetup(&args).is_ok() {
        let _ = std::process::Command::new("/usr/bin/dscacheutil").arg("-flushcache").status();
        return Ok(());
    }
    let quoted: Vec<String> = list.iter().map(|s| sh_quote(s)).collect();
    run_as_admin(&format!(
        "/usr/sbin/networksetup -setdnsservers {} {} && /usr/bin/dscacheutil -flushcache && /usr/bin/killall -HUP mDNSResponder",
        sh_quote(service),
        quoted.join(" ")
    ))
}

pub fn set(provider: &str) -> Result<DnsStatus, String> {
    if !PROVIDERS.iter().any(|(k, _)| *k == provider) {
        return Err(format!("Unknown DNS provider: {provider}"));
    }
    let service = active_service().ok_or("No active network adapter found")?;
    let prev = read_state();
    // The saved state belongs to another service: overwriting it would lose that
    // service's original servers for good, so make the user undo first.
    if prev.as_ref().is_some_and(|p| p.name != service) {
        return Err("DNS was changed on a different network adapter. Undo it first, then apply again.".into());
    }
    // Keep the ORIGINAL servers if a previous set was never undone.
    let first_set = prev.is_none();
    let original = prev.map(|p| p.dns).unwrap_or_else(|| servers(&service));
    save_state(&State { name: service.clone(), dns: original.clone(), provider: provider.into() })?;
    let new: Vec<String> = servers_of(provider).iter().map(|s| s.to_string()).collect();
    if let Err(e) = set_servers(&service, &new) {
        // Nothing changed, so don't leave a state behind that claims it did.
        if first_set {
            let _ = std::fs::remove_file(state_path());
        }
        return Err(e);
    }
    let was = if original.is_empty() { "automatic".to_string() } else { original.join(", ") };
    Ok(DnsStatus { log: Some(format!("{service}: [{was}] -> {provider}")), ..status() })
}

pub fn restore() -> Result<DnsStatus, String> {
    let state = read_state().ok_or("Nothing to restore")?;
    set_servers(&state.name, &state.dns)?;
    let _ = std::fs::remove_file(state_path());
    Ok(DnsStatus { log: Some(format!("{}: DNS restored", state.name)), ..status() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_provider_has_servers() {
        for (key, _) in PROVIDERS {
            let list = servers_of(key);
            assert!(!list.is_empty(), "{key}");
            assert!(list.iter().all(|s| s.parse::<IpAddr>().is_ok()), "{key}");
        }
    }
}
