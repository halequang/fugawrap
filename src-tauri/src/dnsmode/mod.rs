//! DNS mode: switch the active network adapter to a public resolver, and undo it.
//! Changing DNS may need administrator rights; reading the current state does not.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{restore, set, status};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{restore, set, status};

use serde::Serialize;
use serde_json::{Map, Value};

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

#[derive(Serialize)]
pub struct DnsStatus {
    pub active: bool,
    pub provider: Option<String>,
    pub original: Option<Value>,
    pub adapter: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}
