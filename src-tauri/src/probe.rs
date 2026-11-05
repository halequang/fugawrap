//! Connection check: for each target host, work out what kind of blocking (if any)
//! is in the way, and which mode would get around it.
//!
//!   ok   handshake succeeds with the system resolver's answer
//!   dns  system DNS gives a bad answer, but the real address (via DoH) works
//!   sni  TCP connects, the normal handshake fails, a fragmented ClientHello works
//!   ip   the address is unreachable, or even a fragmented handshake fails

use crate::doh;
use crate::tls::{fragment, strategies, write_chunks, Strategy, GAP};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::Serialize;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const TIMEOUT: Duration = Duration::from_secs(6);

/// Certificate-validating TLS client config shared by every probe.
pub fn client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config =
                ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .expect("ring supports the default TLS versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

pub fn is_bogus(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
}

/// Short error names, matching what the Electron build showed.
pub fn io_code(e: &io::Error) -> String {
    use io::ErrorKind::*;
    match e.kind() {
        ConnectionReset => "ECONNRESET".into(),
        ConnectionRefused => "ECONNREFUSED".into(),
        ConnectionAborted => "ECONNABORTED".into(),
        TimedOut | WouldBlock => "timeout".into(),
        UnexpectedEof => "connection closed".into(),
        _ => e.to_string(),
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    pub step: String,
    pub ok: bool,
    pub ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,
}

pub struct Outcome {
    pub ok: bool,
    pub ms: u64,
    pub error: Option<String>,
}

impl Outcome {
    fn into_step(self, step: String, strategy: Option<Strategy>) -> Step {
        Step { step, ok: self.ok, ms: self.ms, error: self.error, strategy }
    }
}

fn timed(f: impl FnOnce() -> Result<(), String>) -> Outcome {
    let started = Instant::now();
    let r = f();
    Outcome { ok: r.is_ok(), ms: started.elapsed().as_millis() as u64, error: r.err() }
}

pub fn tcp_probe(ip: IpAddr, port: u16, timeout: Duration) -> Outcome {
    timed(|| {
        TcpStream::connect_timeout(&SocketAddr::new(ip, port), timeout)
            .map(|_| ())
            .map_err(|e| io_code(&e))
    })
}

/// Full TLS handshake with certificate validation, optionally with a fragmented
/// ClientHello. A DPI block page or an injected reset both show up as failures.
pub fn tls_probe(ip: IpAddr, host: &str, strategy: Option<&Strategy>, timeout: Duration) -> Outcome {
    timed(|| handshake(ip, host, strategy, timeout))
}

fn handshake(ip: IpAddr, host: &str, strategy: Option<&Strategy>, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let sock = TcpStream::connect_timeout(&SocketAddr::new(ip, 443), timeout).map_err(|e| io_code(&e))?;
    handshake_over(sock, host, strategy, deadline)
}

/// Handshake through the local Optimize proxy, the same path a browser takes when
/// the system proxy points at it. The proxy does the splitting.
pub fn proxy_probe(proxy_port: u16, host: &str, timeout: Duration) -> Outcome {
    timed(|| {
        let deadline = Instant::now() + timeout;
        let addr = SocketAddr::from(([127, 0, 0, 1], proxy_port));
        let mut sock = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("proxy: {}", io_code(&e)))?;
        sock.set_read_timeout(Some(timeout)).ok();
        sock.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
            .map_err(|e| io_code(&e))?;
        // Read the reply head byte by byte so no TLS bytes are consumed.
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match sock.read(&mut b) {
                Ok(1) if head.len() < 4096 => head.push(b[0]),
                Ok(_) => return Err("proxy closed the connection".into()),
                Err(e) => return Err(format!("proxy: {}", io_code(&e))),
            }
        }
        let status = String::from_utf8_lossy(&head);
        if !status.starts_with("HTTP/1.1 200") {
            return Err(format!("proxy answered {}", status.lines().next().unwrap_or("")));
        }
        handshake_over(sock, host, None, deadline)
    })
}

fn handshake_over(mut sock: TcpStream, host: &str, strategy: Option<&Strategy>, deadline: Instant) -> Result<(), String> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    sock.set_nodelay(true).ok();
    sock.set_write_timeout(Some(timeout)).ok();
    let name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
    let mut conn = ClientConnection::new(client_config(), name).map_err(|e| e.to_string())?;

    // The first flight is the ClientHello: send it split the chosen way.
    let mut hello = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut hello).map_err(|e| io_code(&e))?;
    }
    write_chunks(&mut sock, &fragment(&hello, strategy), GAP).map_err(|e| io_code(&e))?;

    while conn.is_handshaking() {
        if conn.wants_write() {
            conn.write_tls(&mut sock).map_err(|e| io_code(&e))?;
            continue;
        }
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("timeout")?;
        sock.set_read_timeout(Some(left)).ok();
        match conn.read_tls(&mut sock) {
            Ok(0) => return Err("connection closed".into()),
            Ok(_) => {
                conn.process_new_packets().map_err(|e| e.to_string())?;
            }
            Err(e) => return Err(io_code(&e)),
        }
    }
    Ok(())
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TargetResult {
    pub host: String,
    pub kind: String,
    pub note: String,
    pub sys_ips: Vec<String>,
    pub doh_ips: Vec<String>,
    pub steps: Vec<Step>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<Strategy>,
    /// Only set while Optimize runs: whether the host works through the proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via_optimize: Option<bool>,
}

impl TargetResult {
    fn done(mut self, kind: &str, note: &str) -> Self {
        self.kind = kind.into();
        self.note = note.into();
        self
    }
}

/// Check one host. The verdict (`kind`) always describes the raw network. When
/// Optimize is running (`via_proxy`), the host is also tried through the proxy,
/// and `via_optimize` says whether that path works.
pub fn check_target(host: &str, via_proxy: Option<u16>) -> TargetResult {
    let mut r = check_direct(host);
    if let Some(port) = via_proxy {
        let o = proxy_probe(port, host, TIMEOUT);
        r.via_optimize = Some(o.ok);
        r.steps.push(o.into_step(format!("TLS via Optimize (127.0.0.1:{port})"), None));
    }
    r
}

fn check_direct(host: &str) -> TargetResult {
    let (sys, dohs) = std::thread::scope(|s| {
        let d = s.spawn(|| doh::resolve4(host).unwrap_or_default());
        (doh::system_lookup(host), d.join().unwrap_or_default())
    });
    let mut r = TargetResult {
        host: host.into(),
        kind: String::new(),
        note: String::new(),
        sys_ips: sys.iter().map(|i| i.to_string()).collect(),
        doh_ips: dohs.iter().map(|i| i.to_string()).collect(),
        steps: Vec::new(),
        strategy: None,
        via_optimize: None,
    };
    let sys_ip = sys.iter().copied().find(|ip| !is_bogus(*ip));
    let real_ip = dohs.first().copied().or(sys_ip);

    if let Some(ip) = sys_ip {
        let o = tls_probe(IpAddr::V4(ip), host, None, TIMEOUT);
        let ok = o.ok;
        r.steps.push(o.into_step(format!("TLS {ip} (system DNS)"), None));
        if ok {
            return r.done("ok", "Reachable normally");
        }
    } else {
        let error = if sys.is_empty() {
            "no answer".to_string()
        } else {
            format!("bogus answer {}", r.sys_ips.join(", "))
        };
        r.steps.push(Step { step: "system DNS".into(), ok: false, ms: 0, error: Some(error), strategy: None });
    }
    let Some(real) = real_ip else {
        return r.done("dns", "No usable DNS answer from the system or DoH");
    };
    let real = IpAddr::V4(real);

    if Some(real) != sys_ip.map(IpAddr::V4) {
        let o = tls_probe(real, host, None, TIMEOUT);
        let ok = o.ok;
        r.steps.push(o.into_step(format!("TLS {real} (DoH)"), None));
        if ok {
            return r.done("dns", "System DNS returns a wrong address");
        }
    }

    let tcp = tcp_probe(real, 443, TIMEOUT);
    let tcp_ok = tcp.ok;
    r.steps.push(tcp.into_step(format!("TCP {real}:443"), None));
    if !tcp_ok {
        return r.done("ip", "Address is unreachable");
    }

    for s in strategies() {
        let o = tls_probe(real, host, Some(&s), TIMEOUT);
        let ok = o.ok;
        r.steps.push(o.into_step(format!("TLS {real} fragmented"), Some(s.clone())));
        if ok {
            r.strategy = Some(s);
            return r.done("sni", "Blocked by host name; splitting the ClientHello works");
        }
    }
    r.done("ip", "Handshake fails even when fragmented")
}

/// Overall block type and the mode that fixes it.
pub fn summarize(kinds: &[&str]) -> (Option<String>, Option<String>) {
    let blocked: Vec<&str> = kinds.iter().copied().filter(|k| *k != "ok").collect();
    let kind = if blocked.is_empty() {
        return (None, None);
    } else if blocked.contains(&"ip") {
        "ip"
    } else if blocked.contains(&"sni") {
        if kinds.contains(&"ok") { "mixed" } else { "sni" }
    } else {
        "dns"
    };
    let recommend = match kind {
        "dns" => "dns",
        "ip" => "tunnel",
        _ => "optimize",
    };
    (Some(kind.into()), Some(recommend.into()))
}

#[derive(Serialize)]
pub struct Report {
    pub at: u64,
    pub targets: Vec<TargetResult>,
    pub kind: Option<String>,
    pub recommend: Option<String>,
    /// Only set while Optimize runs: how many hosts work through it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optimize: Option<OptimizeCheck>,
}

#[derive(Serialize)]
pub struct OptimizeCheck {
    pub port: u16,
    pub working: usize,
    pub total: usize,
}

pub fn diagnose(hosts: &[String], via_proxy: Option<u16>, on_progress: impl Fn(&TargetResult) + Sync) -> Report {
    let targets: Vec<TargetResult> = std::thread::scope(|s| {
        let on = &on_progress;
        let handles: Vec<_> = hosts
            .iter()
            .map(|h| {
                s.spawn(move || {
                    let r = check_target(h, via_proxy);
                    on(&r);
                    r
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("check thread panicked")).collect()
    });
    let kinds: Vec<&str> = targets.iter().map(|t| t.kind.as_str()).collect();
    let (kind, recommend) = summarize(&kinds);
    let optimize = via_proxy.map(|port| OptimizeCheck {
        port,
        working: targets.iter().filter(|t| t.via_optimize == Some(true)).count(),
        total: targets.len(),
    });
    let at = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    Report { at, targets, kind, recommend, optimize }
}

#[derive(Serialize)]
pub struct Measure {
    pub strategy: Option<Strategy>,
    pub tried: Vec<Step>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The first fragmentation strategy that completes a handshake with `host`.
pub fn measure_strategy(host: &str) -> Measure {
    let ip = doh::resolve4(host)
        .ok()
        .and_then(|v| v.first().copied())
        .or_else(|| doh::system_lookup(host).into_iter().find(|ip| !is_bogus(*ip)));
    let Some(ip) = ip else {
        return Measure { strategy: None, tried: vec![], error: Some(format!("Could not resolve {host}")) };
    };
    let mut tried = Vec::new();
    for s in strategies() {
        let o = tls_probe(IpAddr::V4(ip), host, Some(&s), TIMEOUT);
        let ok = o.ok;
        tried.push(o.into_step(format!("TLS {ip} fragmented"), Some(s.clone())));
        if ok {
            return Measure { strategy: Some(s), tried, error: None };
        }
    }
    Measure { strategy: None, tried, error: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_picks_the_mode_that_fixes_the_worst_block() {
        let s = |k: &[&str]| summarize(k);
        let some = |a: &str, b: &str| (Some(a.to_string()), Some(b.to_string()));
        assert_eq!(s(&["ok", "ok"]), (None, None));
        assert_eq!(s(&["dns", "ok"]), some("dns", "dns"));
        assert_eq!(s(&["sni", "sni"]), some("sni", "optimize"));
        assert_eq!(s(&["sni", "ok"]), some("mixed", "optimize"));
        assert_eq!(s(&["dns", "sni"]), some("sni", "optimize"));
        assert_eq!(s(&["ip", "sni"]), some("ip", "tunnel"));
    }

    /// Live network check, opt-in: `cargo test -- --ignored --nocapture live_`.
    /// Repeats each handshake to show whether a block is consistent.
    #[test]
    #[ignore]
    fn live_handshakes() {
        let host = std::env::var("FUGAWRAP_HOST").unwrap_or_else(|_| "store.steampowered.com".into());
        let sys = doh::system_lookup(&host);
        let dohs = doh::resolve4(&host).unwrap_or_default();
        println!("{host}: system {sys:?}, DoH {dohs:?}");
        let mut ips: Vec<Ipv4Addr> = sys.iter().chain(dohs.iter()).copied().collect();
        ips.dedup();
        let mut ways: Vec<Option<Strategy>> = vec![None];
        ways.extend(strategies().into_iter().map(Some));
        for ip in ips.into_iter().take(2) {
            for s in &ways {
                let results: Vec<String> = (0..3)
                    .map(|_| {
                        let o = tls_probe(IpAddr::V4(ip), &host, s.as_ref(), TIMEOUT);
                        if o.ok { "ok".into() } else { o.error.unwrap_or_default() }
                    })
                    .collect();
                println!("  {ip:<16} {:<28} {}", crate::tls::describe(s.as_ref()), results.join(", "));
            }
        }
    }

    /// Live check of the whole Optimize path, opt-in:
    /// `cargo test -- --ignored --nocapture live_`. Starts the real proxy (DoH
    /// resolver, each split method) without touching the system proxy setting.
    #[test]
    #[ignore]
    fn live_through_proxy() {
        let host = std::env::var("FUGAWRAP_HOST").unwrap_or_else(|_| "store.steampowered.com".into());
        let resolver = Arc::new(doh::Resolver::new(Duration::from_secs(300)));
        let mut ways: Vec<Option<Strategy>> = vec![None];
        ways.extend(strategies().into_iter().map(Some));
        for s in ways {
            let r = resolver.clone();
            let p = crate::proxy::FragProxy::start(0, Arc::new(move |h| r.resolve(h)), s.clone(), Arc::new(|_| {}))
                .unwrap();
            let results: Vec<String> = (0..3)
                .map(|_| {
                    let o = proxy_probe(p.port(), &host, TIMEOUT);
                    if o.ok { "ok".into() } else { o.error.unwrap_or_default() }
                })
                .collect();
            println!("  via proxy  {:<28} {}", crate::tls::describe(s.as_ref()), results.join(", "));
            p.stop();
        }
    }

    /// Live check of many sites through one proxy with the default split, opt-in:
    /// `FUGAWRAP_HOSTS="a.com b.com" cargo test -- --ignored --nocapture live_sites`.
    /// Each site connects twice: the second one uses whatever the first learned.
    /// Certificates are validated, so a server that serves the wrong one fails.
    #[test]
    #[ignore]
    fn live_sites_through_proxy() {
        let hosts = std::env::var("FUGAWRAP_HOSTS").unwrap_or_else(|_| "store.steampowered.com id.plaync.com".into());
        let resolver = Arc::new(doh::Resolver::new(Duration::from_secs(300)));
        let log = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = log.clone();
        let p = crate::proxy::FragProxy::start(
            0,
            Arc::new(move |h| resolver.resolve(h)),
            Some(Strategy::sni()),
            Arc::new(move |m| sink.lock().unwrap().push(m)),
        )
        .unwrap();
        let port = p.port();
        let threads: Vec<_> = hosts
            .split_whitespace()
            .map(|h| {
                let h = h.to_string();
                std::thread::spawn(move || {
                    let r: Vec<String> = (0..2)
                        .map(|_| {
                            let o = proxy_probe(port, &h, Duration::from_secs(20));
                            if o.ok { format!("ok {}ms", o.ms) } else { o.error.unwrap_or_default() }
                        })
                        .collect();
                    (h, r)
                })
            })
            .collect();
        let mut failed = 0;
        for t in threads {
            let (h, r) = t.join().unwrap();
            failed += r.iter().filter(|x| !x.starts_with("ok")).count();
            println!("  {h:<26} {}", r.join(" | "));
        }
        println!("--- proxy log\n{}", log.lock().unwrap().join("\n"));
        println!("--- {failed} failed handshakes");
        p.stop();
    }

    #[test]
    fn bogus_answers_are_flagged() {
        for ip in ["0.0.0.0", "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.20.0.1", "169.254.1.1", "100.64.0.1"] {
            assert!(is_bogus(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["23.45.67.89", "172.32.0.1", "8.8.8.8"] {
            assert!(!is_bogus(ip.parse().unwrap()), "{ip}");
        }
    }
}
