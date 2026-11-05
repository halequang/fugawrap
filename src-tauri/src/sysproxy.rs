//! Point the Windows (WinINET) system proxy at the local fragmenting proxy, and put
//! the user's previous settings back. Per-user settings, so no admin rights needed.
//!
//! The previous settings are saved to disk before anything changes, so a crash or
//! a force-kill can be undone on the next start.

use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;
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

fn ours(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

pub struct SysProxy {
    backup: PathBuf,
}

impl SysProxy {
    pub fn new(backup: PathBuf) -> Self {
        Self { backup }
    }

    fn load_backup(&self) -> Option<Snapshot> {
        serde_json::from_str(&std::fs::read_to_string(&self.backup).ok()?).ok()
    }

    pub fn enable(&self, port: u16) -> Result<(), String> {
        // Keep the oldest backup: if one exists, the current values are already ours.
        if self.load_backup().is_none() {
            let json = serde_json::to_string(&read()?).map_err(|e| e.to_string())?;
            std::fs::write(&self.backup, json).map_err(|e| format!("Could not save proxy backup: {e}"))?;
        }
        write(&Snapshot {
            proxy_enable: 1,
            proxy_server: Some(ours(port)),
            proxy_override: Some("<local>;localhost;127.*;10.*;192.168.*".into()),
            auto_config_url: None, // a PAC script would take precedence over our proxy
        })
    }

    /// Put the saved settings back. Returns whether there was anything to restore.
    pub fn restore(&self) -> Result<bool, String> {
        let Some(backup) = self.load_backup() else { return Ok(false) };
        write(&backup)?;
        let _ = std::fs::remove_file(&self.backup);
        Ok(true)
    }

    /// Startup check after an unclean exit. Restores the backup if there is one;
    /// otherwise turns off a system proxy that still points at our port while
    /// nothing listens there (backup lost, e.g. the app was renamed or moved).
    pub fn recover(&self, port: u16) -> Result<Option<&'static str>, String> {
        if self.restore()? {
            return Ok(Some("Restored the proxy settings left over from an unclean exit"));
        }
        let now = read()?;
        let listening =
            TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(300)).is_ok();
        if now.proxy_enable != 0 && now.proxy_server.as_deref() == Some(ours(port).as_str()) && !listening {
            write(&Snapshot { proxy_enable: 0, proxy_server: None, proxy_override: None, ..now })?;
            return Ok(Some("Turned off a system proxy that pointed at a FugaWrap proxy that was no longer running"));
        }
        Ok(None)
    }
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
