//! User settings, stored as JSON in the app's config folder.

use crate::tls::Strategy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub targets: Vec<String>,
    pub provider: String,
    pub strategy: Option<Strategy>,
    pub proxy_port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            targets: ["store.steampowered.com", "api.steampowered.com", "steamcommunity.com"]
                .map(String::from)
                .to_vec(),
            provider: "google".into(),
            strategy: Some(Strategy::sni()),
            proxy_port: 18787,
        }
    }
}

pub struct Store {
    path: PathBuf,
    data: Mutex<Settings>,
}

impl Store {
    pub fn load(path: PathBuf) -> Self {
        let data = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self { path, data: Mutex::new(data) }
    }

    pub fn get(&self) -> Settings {
        self.data.lock().unwrap().clone()
    }

    pub fn update(&self, f: impl FnOnce(&mut Settings)) -> Result<Settings, String> {
        let mut data = self.data.lock().unwrap();
        f(&mut data);
        let json = serde_json::to_string_pretty(&*data).map_err(|e| e.to_string())?;
        std::fs::write(&self.path, json).map_err(|e| format!("Could not save settings: {e}"))?;
        Ok(data.clone())
    }
}

/// Lower-case, de-duplicate and keep only plausible host names.
pub fn clean_targets(targets: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in targets {
        let t = t.trim().to_ascii_lowercase();
        if is_host_name(&t) && !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// A dotted DNS name such as `store.steampowered.com`. Single words ("bad",
/// "host") are rejected: they can't be public sites.
pub fn is_host_name(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    s.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_targets_filters_and_dedupes() {
        let input = ["Store.SteamPowered.com ", "store.steampowered.com", "bad host", "", "a-b.c"].map(String::from);
        assert_eq!(clean_targets(&input), vec!["store.steampowered.com", "a-b.c"]);
    }

    #[test]
    fn host_names_need_dotted_valid_labels() {
        for ok in ["store.steampowered.com", "a-b.c", "www.cloudflare.com", "x1.y2"] {
            assert!(is_host_name(ok), "{ok}");
        }
        let long_label = format!("{}.com", "a".repeat(64));
        let too_long = format!("{}com", "a.".repeat(127)); // 257 characters
        let bad = ["bad", "host", "", ".com", "a..b", "-a.com", "a-.com", "a_b.com", "a.b c", &long_label, &too_long];
        for b in bad {
            assert!(!is_host_name(b), "{b}");
        }
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        let s: Settings = serde_json::from_str(r#"{"provider":"adguard"}"#).unwrap();
        assert_eq!(s.provider, "adguard");
        assert_eq!(s.proxy_port, 18787);
        assert_eq!(s.strategy, Some(Strategy::sni()));
    }
}
