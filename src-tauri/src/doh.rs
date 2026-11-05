//! DNS-over-HTTPS A-record lookups, addressed by IP so they never depend on the
//! (possibly poisoned) system resolver. Both certificates carry an IP SAN.

use serde::Deserialize;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const ENDPOINTS: [(&str, &str); 2] = [("1.1.1.1", "/dns-query"), ("8.8.8.8", "/resolve")];
const TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Deserialize)]
struct Answer {
    #[serde(rename = "type")]
    typ: u16,
    data: String,
}

#[derive(Deserialize)]
struct Reply {
    #[serde(rename = "Answer", default)]
    answer: Vec<Answer>,
}

pub fn resolve4(name: &str) -> Result<Vec<Ipv4Addr>, String> {
    let agent = ureq::AgentBuilder::new().timeout(TIMEOUT).build();
    let mut last = None;
    for (ip, path) in ENDPOINTS {
        let reply = agent
            .get(&format!("https://{ip}{path}"))
            .query("name", name)
            .query("type", "A")
            .set("accept", "application/dns-json")
            .call()
            .map_err(|e| e.to_string())
            .and_then(|r| r.into_json::<Reply>().map_err(|e| e.to_string()));
        match reply {
            Ok(r) => {
                let ips: Vec<Ipv4Addr> = r
                    .answer
                    .into_iter()
                    .filter(|a| a.typ == 1)
                    .filter_map(|a| a.data.parse().ok())
                    .collect();
                if !ips.is_empty() {
                    return Ok(ips);
                }
                last = Some(format!("DoH {ip}: no A records for {name}"));
            }
            Err(e) => last = Some(format!("DoH {ip}: {e}")),
        }
    }
    Err(last.unwrap_or_else(|| format!("DoH: no A records for {name}")))
}

#[cfg(test)]
mod tests {
    /// Live network check, opt-in: `cargo test -- --ignored --nocapture live_`.
    #[test]
    #[ignore]
    fn live_doh() {
        println!("DoH store.steampowered.com: {:?}", super::resolve4("store.steampowered.com"));
    }
}

/// IPv4 answers from the system resolver (what ordinary apps get).
pub fn system_lookup(host: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if let Ok(addrs) = (host, 443).to_socket_addrs() {
        for a in addrs {
            if let IpAddr::V4(ip) = a.ip() {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// Resolver for the proxy: DoH first, system DNS as a fallback, with a TTL cache.
pub struct Resolver {
    ttl: Duration,
    cache: Mutex<HashMap<String, (IpAddr, Instant)>>,
}

impl Resolver {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, cache: Mutex::new(HashMap::new()) }
    }

    pub fn resolve(&self, host: &str) -> io::Result<IpAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(ip);
        }
        if let Some((ip, expires)) = self.cache.lock().unwrap().get(host) {
            if *expires > Instant::now() {
                return Ok(*ip);
            }
        }
        let ip = match resolve4(host) {
            Ok(ips) => IpAddr::V4(ips[0]),
            Err(_) => IpAddr::V4(*system_lookup(host).first().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("Could not resolve {host}"))
            })?),
        };
        self.cache.lock().unwrap().insert(host.to_owned(), (ip, Instant::now() + self.ttl));
        Ok(ip)
    }
}
