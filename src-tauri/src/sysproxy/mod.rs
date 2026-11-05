//! Point the system proxy at the local fragmenting proxy, and put the user's
//! previous settings back. Per-user settings, so no admin rights needed.
//!
//! The previous settings are saved to disk before anything changes, so a crash or
//! a force-kill can be undone on the next start. Each platform module provides
//! `Snapshot`, `read`, `write`, `ours`, `points_at` and `turned_off`.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as imp;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

use imp::Snapshot;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

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
        let now = imp::read()?;
        // Keep the oldest backup: if one exists, the current values are already ours.
        if self.load_backup().is_none() {
            let json = serde_json::to_string(&now).map_err(|e| e.to_string())?;
            std::fs::write(&self.backup, json).map_err(|e| format!("Could not save proxy backup: {e}"))?;
        }
        imp::write(&imp::ours(port, &now))
    }

    /// Put the saved settings back. Returns whether there was anything to restore.
    pub fn restore(&self) -> Result<bool, String> {
        let Some(backup) = self.load_backup() else { return Ok(false) };
        imp::write(&backup)?;
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
        let now = imp::read()?;
        let listening =
            TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(300)).is_ok();
        if imp::points_at(&now, port) && !listening {
            imp::write(&imp::turned_off(now, port))?;
            return Ok(Some("Turned off a system proxy that pointed at a FugaWrap proxy that was no longer running"));
        }
        Ok(None)
    }
}
