//! DNS mode: switch the active adapter to a public resolver with DNS-over-HTTPS,
//! and undo it. Changing DNS needs administrator rights (one UAC prompt per
//! action); reading the current state does not. The script is shared with the
//! Electron build.

use crate::ps::{ps_quote, run_ps, run_ps_elevated};
use serde::Serialize;
use serde_json::{Map, Value};
use std::path::PathBuf;

const SCRIPT: &str = include_str!("../../src/scripts/dns.ps1");

pub const PROVIDERS: [(&str, &str); 5] = [
    ("google", "Google"),
    ("opendns", "OpenDNS"),
    ("adguard", "AdGuard"),
    ("alibaba", "Alibaba"),
    ("cloudflare", "Cloudflare"),
];

pub fn providers_json() -> Map<String, Value> {
    PROVIDERS.iter().map(|(k, v)| (k.to_string(), Value::from(*v))).collect()
}

fn state_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())).join("FugaWrap")
}

fn read_state() -> Option<Value> {
    let text = std::fs::read_to_string(state_dir().join("dns-state.json")).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

fn last_log_line() -> String {
    std::fs::read_to_string(state_dir().join("dns.log"))
        .ok()
        .and_then(|t| t.trim().lines().last().map(str::to_string))
        .unwrap_or_default()
}

#[derive(Serialize)]
pub struct DnsStatus {
    pub active: bool,
    pub provider: Option<String>,
    pub original: Option<Value>,
    pub adapter: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}

fn current_adapter() -> Option<Value> {
    let r = run_ps(
        "$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
if ($route) {
  $a = Get-NetAdapter -InterfaceIndex $route.ifIndex
  @{ name = $a.Name; servers = @((Get-DnsClientServerAddress -InterfaceIndex $route.ifIndex).ServerAddresses) } | ConvertTo-Json -Compress
}",
    )
    .ok()?;
    serde_json::from_str(&r.stdout).ok()
}

pub fn status() -> DnsStatus {
    let state = read_state();
    DnsStatus {
        active: state.is_some(),
        provider: state.as_ref().and_then(|s| s.get("provider")?.as_str().map(String::from)),
        original: state.as_ref().and_then(|s| s.get("dns").cloned()),
        adapter: current_adapter(),
        log: None,
    }
}

fn run(mode: &str, provider: &str) -> Result<DnsStatus, String> {
    let script = format!("$Mode = {}; $Provider = {}\n{SCRIPT}", ps_quote(mode), ps_quote(provider));
    let r = run_ps_elevated(&script)?;
    match r.code {
        0 => Ok(DnsStatus { log: Some(last_log_line()), ..status() }),
        2 => Err("No active network adapter found".into()),
        3 => Err("Nothing to restore".into()),
        4 => Err("DNS was changed on a different network adapter. Undo it first, then apply again.".into()),
        code => Err(format!("DNS script failed (exit {code}): {}", last_log_line())),
    }
}

pub fn set(provider: &str) -> Result<DnsStatus, String> {
    if !PROVIDERS.iter().any(|(k, _)| *k == provider) {
        return Err(format!("Unknown DNS provider: {provider}"));
    }
    run("set", provider)
}

pub fn restore() -> Result<DnsStatus, String> {
    run("restore", "")
}
