//! Windows: the per-user WinINET proxy setting in the registry.

use serde::{Deserialize, Serialize};
use winreg::enums::{HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE};
use winreg::RegKey;

const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    #[serde(rename = "ProxyEnable", default)]
    pub proxy_enable: u32,
    #[serde(rename = "ProxyServer", default)]
    pub proxy_server: Option<String>,
    #[serde(rename = "ProxyOverride", default)]
    pub proxy_override: Option<String>,
    #[serde(rename = "AutoConfigURL", default)]
    pub auto_config_url: Option<String>,
}

fn key(write: bool) -> Result<RegKey, String> {
    let flags = if write { KEY_QUERY_VALUE | KEY_SET_VALUE } else { KEY_QUERY_VALUE };
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(KEY, flags)
        .map_err(|e| format!("Could not open Internet Settings: {e}"))
}

pub fn read() -> Result<Snapshot, String> {
    let k = key(false)?;
    let s = |name: &str| k.get_value::<String, _>(name).ok().filter(|v| !v.is_empty());
    Ok(Snapshot {
        proxy_enable: k.get_value::<u32, _>("ProxyEnable").unwrap_or(0),
        proxy_server: s("ProxyServer"),
        proxy_override: s("ProxyOverride"),
        auto_config_url: s("AutoConfigURL"),
    })
}

pub fn write(s: &Snapshot) -> Result<(), String> {
    let k = key(true)?;
    let err = |e: std::io::Error| format!("Could not change the system proxy: {e}");
    k.set_value("ProxyEnable", &u32::from(s.proxy_enable != 0)).map_err(err)?;
    for (name, value) in [
        ("ProxyServer", &s.proxy_server),
        ("ProxyOverride", &s.proxy_override),
        ("AutoConfigURL", &s.auto_config_url),
    ] {
        match value {
            Some(v) => k.set_value(name, v).map_err(err)?,
            None => {
                let _ = k.delete_value(name);
            }
        }
    }
    notify();
    Ok(())
}

/// Tell running apps the settings changed (INTERNET_OPTION_SETTINGS_CHANGED, _REFRESH).
fn notify() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    // SAFETY: both options take no buffer; a null handle applies them globally.
    unsafe {
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}

fn addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

pub fn ours(port: u16, _now: &Snapshot) -> Snapshot {
    Snapshot {
        proxy_enable: 1,
        proxy_server: Some(addr(port)),
        proxy_override: Some("<local>;localhost;127.*;10.*;192.168.*".into()),
        auto_config_url: None, // a PAC script would take precedence over our proxy
    }
}

pub fn points_at(s: &Snapshot, port: u16) -> bool {
    s.proxy_enable != 0 && s.proxy_server.as_deref() == Some(addr(port).as_str())
}

pub fn turned_off(now: Snapshot, _port: u16) -> Snapshot {
    Snapshot { proxy_enable: 0, proxy_server: None, proxy_override: None, ..now }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_json_matches_the_electron_format() {
        let s: Snapshot =
            serde_json::from_str(r#"{"ProxyEnable":0,"ProxyOverride":null,"AutoConfigURL":null,"ProxyServer":null}"#)
                .unwrap();
        assert_eq!(s, Snapshot::default());
        let back: Snapshot = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }
}
