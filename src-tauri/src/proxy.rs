//! Local HTTP proxy that splits each TLS ClientHello it forwards.
//!
//! RevoltWarp does this in the kernel with WinDivert, which catches every app but
//! needs a driver. A proxy needs nothing installed and covers every app that uses
//! the Windows system proxy; apps that ignore it are not covered.

use crate::tls::{describe, fragment, is_client_hello, record_length, write_chunks, Strategy, GAP};
use serde::Serialize;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_HEAD: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const HELLO_WAIT: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for the server's answer to a split ClientHello before
/// assuming it was accepted. Servers answer within one round trip.
const FIRST_REPLY_WAIT: Duration = Duration::from_secs(5);
const ALERT: u8 = 0x15;

pub type ResolveFn = Arc<dyn Fn(&str) -> io::Result<IpAddr> + Send + Sync>;
pub type LogFn = Arc<dyn Fn(String) + Send + Sync>;

#[derive(Default)]
pub struct Stats {
    connections: AtomicU64,
    fragmented: AtomicU64,
    errors: AtomicU64,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatsView {
    pub connections: u64,
    pub fragmented: u64,
    pub errors: u64,
}

#[derive(Debug)]
pub struct Head {
    pub method: String,
    pub target: String,
    pub version: String,
    pub header_lines: Vec<String>,
    pub rest: Vec<u8>,
}

/// Parse a proxy request head. `Ok(None)` until the head is complete.
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>, String> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { return Ok(None) };
    let head = String::from_utf8_lossy(&buf[..end]);
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split(' ');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v)) if !m.is_empty() && !t.is_empty() && !v.is_empty() => Ok(Some(Head {
            method: m.into(),
            target: t.into(),
            version: v.into(),
            header_lines: lines.map(String::from).collect(),
            rest: buf[end + 4..].to_vec(),
        })),
        _ => Err("Malformed request line".into()),
    }
}

pub fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    let bad = || format!("Bad host: {s}");
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or_else(bad)?;
        (h, after.strip_prefix(':'))
    } else {
        match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    if host.is_empty() {
        return Err(bad());
    }
    let port = match port {
        Some(p) => p.parse().map_err(|_| bad())?,
        None => default_port,
    };
    Ok((host.into(), port))
}

struct Ctx {
    resolve: ResolveFn,
    strategy: RwLock<Option<Strategy>>,
    /// "host:port" -> the split that host accepted after it rejected the main one
    /// (`None`: no split). Cleared when the strategy changes.
    fallback: Mutex<HashMap<String, Option<Strategy>>>,
    stats: Stats,
    log: LogFn,
    live: Mutex<HashMap<u64, TcpStream>>,
    next_id: AtomicU64,
}

pub struct FragProxy {
    port: u16,
    stop: Arc<AtomicBool>,
    ctx: Arc<Ctx>,
    accept: Option<JoinHandle<()>>,
}

impl FragProxy {
    pub fn start(port: u16, resolve: ResolveFn, strategy: Option<Strategy>, log: LogFn) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = Arc::new(Ctx {
            resolve,
            strategy: RwLock::new(strategy),
            fallback: Mutex::new(HashMap::new()),
            stats: Stats::default(),
            log,
            live: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        });
        let accept = {
            let (stop, ctx) = (stop.clone(), ctx.clone());
            thread::spawn(move || {
                for conn in listener.incoming() {
                    if stop.load(Relaxed) {
                        break;
                    }
                    if let Ok(client) = conn {
                        let ctx = ctx.clone();
                        thread::spawn(move || ctx.handle(client));
                    }
                }
            })
        };
        Ok(Self { port, stop, ctx, accept: Some(accept) })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn stats(&self) -> StatsView {
        let s = &self.ctx.stats;
        StatsView {
            connections: s.connections.load(Relaxed),
            fragmented: s.fragmented.load(Relaxed),
            errors: s.errors.load(Relaxed),
        }
    }

    pub fn set_strategy(&self, s: Option<Strategy>) {
        *self.ctx.strategy.write().unwrap() = s;
        self.ctx.fallback.lock().unwrap().clear();
    }

    pub fn stop(mut self) {
        self.stop.store(true, Relaxed);
        // Wake the blocking accept() so the thread sees the flag.
        let _ = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], self.port)), Duration::from_secs(1));
        for (_, s) in self.ctx.live.lock().unwrap().drain() {
            let _ = s.shutdown(Shutdown::Both);
        }
        if let Some(t) = self.accept.take() {
            let _ = t.join();
        }
    }
}

impl Ctx {
    fn handle(self: Arc<Self>, mut client: TcpStream) {
        let _ = client.set_read_timeout(Some(HEAD_TIMEOUT));
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let head = loop {
            match parse_head(&buf) {
                Err(e) => return self.fail(&mut client, &e, "400 Bad Request"),
                Ok(Some(h)) => break h,
                Ok(None) if buf.len() > MAX_HEAD => {
                    return self.fail(&mut client, "Request head too large", "431 Request Header Fields Too Large")
                }
                Ok(None) => {}
            }
            match client.read(&mut tmp) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        };
        self.stats.connections.fetch_add(1, Relaxed);
        let upstream = if head.method.eq_ignore_ascii_case("CONNECT") {
            self.open_tunnel(&mut client, head)
        } else {
            self.open_forward(head).map(|up| (up, Vec::new()))
        };
        match upstream {
            Ok((up, reply)) => self.pipe(client, up, &reply),
            Err(e) => self.fail(&mut client, &e, "502 Bad Gateway"),
        }
    }

    fn fail(&self, client: &mut TcpStream, msg: &str, status: &str) {
        self.stats.errors.fetch_add(1, Relaxed);
        (self.log)(format!("error: {msg}"));
        let _ = client.write_all(format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n").as_bytes());
        let _ = client.shutdown(Shutdown::Both);
    }

    fn connect_upstream(&self, host: &str, port: u16) -> Result<TcpStream, String> {
        let ip = (self.resolve)(host).map_err(|e| e.to_string())?;
        let up = TcpStream::connect_timeout(&SocketAddr::new(ip, port), CONNECT_TIMEOUT)
            .map_err(|e| format!("{host}:{port}: {e}"))?;
        up.set_nodelay(true).ok();
        Ok(up)
    }

    /// CONNECT host:443: answer 200, then send the first ClientHello split.
    ///
    /// Some servers refuse a ClientHello spread over two TLS records, although
    /// RFC 8446 requires them to accept it (id.plaync.com answers decode_error).
    /// When a server answers the record split with an alert or by closing, this
    /// reconnects and resends the same ClientHello with a TCP-only split, then
    /// unsplit. The browser has received nothing from the server yet, so the retry
    /// is invisible to it. The split that worked is remembered per host.
    ///
    /// Returns the upstream socket and the server's first bytes, which the caller
    /// must pass to the client before piping.
    fn open_tunnel(&self, client: &mut TcpStream, head: Head) -> Result<(TcpStream, Vec<u8>), String> {
        let (host, port) = split_host_port(&head.target, 443)?;
        let mut up = self.connect_upstream(&host, port)?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").map_err(|e| e.to_string())?;
        let hello = read_client_hello(client, head.rest);
        if hello.is_empty() {
            return Ok((up, Vec::new()));
        }
        let key = format!("{host}:{port}");
        let remembered = self.fallback.lock().unwrap().get(&key).cloned();
        let plans = match remembered {
            Some(plan) => vec![plan],
            None => plans_for(&hello, self.strategy.read().unwrap().clone()),
        };
        for (i, plan) in plans.iter().enumerate() {
            if i > 0 {
                up = self.connect_upstream(&host, port)?;
            }
            let chunks = fragment(&hello, plan.as_ref());
            if chunks.len() > 1 {
                self.stats.fragmented.fetch_add(1, Relaxed);
            }
            write_chunks(&mut up, &chunks, GAP).map_err(|e| e.to_string())?;
            if plans.len() == 1 {
                return Ok((up, Vec::new()));
            }
            let (rejected, reply) = first_reply(&mut up);
            if rejected && i + 1 < plans.len() {
                (self.log)(format!("{key} rejected {}, retrying", describe(plan.as_ref())));
                continue;
            }
            if i > 0 && !rejected {
                (self.log)(format!("{key}: using {}", describe(plan.as_ref())));
                self.fallback.lock().unwrap().insert(key, plan.clone());
            }
            return Ok((up, reply));
        }
        unreachable!("plans is never empty")
    }

    /// Plain-HTTP request in absolute form: rewrite to origin form and pass through.
    fn open_forward(&self, head: Head) -> Result<TcpStream, String> {
        let rest = head
            .target
            .strip_prefix("http://")
            .ok_or_else(|| format!("Unsupported proxy target {}", head.target))?;
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let path = if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
        let (host, port) = split_host_port(authority, 80)?;
        let mut up = self.connect_upstream(&host, port)?;
        let headers: Vec<&String> = head
            .header_lines
            .iter()
            .filter(|h| {
                let l = h.to_ascii_lowercase();
                !l.starts_with("proxy-connection:") && !l.starts_with("connection:")
            })
            .collect();
        let mut out = format!("{} {} {}\r\n", head.method, path, head.version);
        for h in headers {
            out.push_str(h);
            out.push_str("\r\n");
        }
        out.push_str("Connection: close\r\n\r\n");
        up.write_all(out.as_bytes()).map_err(|e| e.to_string())?;
        up.write_all(&head.rest).map_err(|e| e.to_string())?;
        Ok(up)
    }

    fn track(&self, s: &TcpStream) -> Option<u64> {
        let id = self.next_id.fetch_add(1, Relaxed);
        self.live.lock().unwrap().insert(id, s.try_clone().ok()?);
        Some(id)
    }

    fn pipe(&self, mut client: TcpStream, up: TcpStream, reply: &[u8]) {
        let _ = client.set_read_timeout(None);
        if client.write_all(reply).is_err() {
            return;
        }
        let ids = [self.track(&client), self.track(&up)];
        if let (Ok(mut from_client), Ok(mut to_up)) = (client.try_clone(), up.try_clone()) {
            let t = thread::spawn(move || {
                let _ = io::copy(&mut from_client, &mut to_up);
                let _ = to_up.shutdown(Shutdown::Write);
            });
            let (mut from_up, mut to_client) = (up, client);
            let _ = io::copy(&mut from_up, &mut to_client);
            let _ = to_client.shutdown(Shutdown::Both);
            let _ = from_up.shutdown(Shutdown::Both);
            let _ = t.join();
        }
        let mut live = self.live.lock().unwrap();
        for id in ids.into_iter().flatten() {
            live.remove(&id);
        }
    }
}

/// What to try, in order, for one ClientHello. Fallbacks only exist for a record
/// split: a TCP split at the same place, then no split.
fn plans_for(hello: &[u8], main: Option<Strategy>) -> Vec<Option<Strategy>> {
    match main {
        Some(s) if is_client_hello(hello) && s.record != Some(false) => {
            let tcp = Strategy { record: Some(false), ..s.clone() };
            vec![Some(s), Some(tcp), None]
        }
        other => vec![other],
    }
}

/// Wait for the server's first answer. `rejected` when it is a TLS alert, or the
/// server closed or reset the connection without answering. A timeout counts as
/// accepted (nothing is lost: the client's bytes wait in the socket buffer).
fn first_reply(up: &mut TcpStream) -> (bool, Vec<u8>) {
    let _ = up.set_read_timeout(Some(FIRST_REPLY_WAIT));
    let mut buf = vec![0u8; 16 * 1024];
    let result = match up.read(&mut buf) {
        Ok(0) => (true, Vec::new()),
        Ok(n) => (buf[0] == ALERT, buf[..n].to_vec()),
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => (false, Vec::new()),
        Err(_) => (true, Vec::new()),
    };
    let _ = up.set_read_timeout(None);
    result
}

/// Collect the whole first TLS record (a ClientHello can span several reads).
fn read_client_hello(client: &mut TcpStream, mut buf: Vec<u8>) -> Vec<u8> {
    let complete = |b: &[u8]| !b.is_empty() && (!is_client_hello(b) || b.len() >= record_length(b));
    let deadline = Instant::now() + HELLO_WAIT;
    let mut tmp = [0u8; 4096];
    while !complete(&buf) {
        let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else { break };
        let _ = client.set_read_timeout(Some(left));
        match client.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let _ = client.set_read_timeout(None);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::{records, sample_client_hello};
    use std::sync::mpsc;

    /// A minimal handshake record, standing in for a ServerHello.
    const SERVER_HELLO: [u8; 6] = [0x16, 0x03, 0x03, 0x00, 0x01, 0x02];
    const DECODE_ERROR: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32];

    /// Fake upstream that reports every read it gets, and answers the first one
    /// the way a server answers a ClientHello.
    fn upstream() -> (u16, mpsc::Receiver<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let tx = tx.clone();
                thread::spawn(move || {
                    let mut s = s;
                    let mut buf = [0u8; 65536];
                    let mut first = true;
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                        if std::mem::take(&mut first) && buf[0] == 0x16 {
                            let _ = s.write_all(&SERVER_HELLO);
                        }
                    }
                });
            }
        });
        (port, rx)
    }

    /// Fake server like id.plaync.com: answers decode_error and closes when the
    /// ClientHello comes in more than one record. Reports how each connection's
    /// hello arrived (number of records).
    fn picky_upstream(hello_len: usize) -> (u16, mpsc::Receiver<usize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let tx = tx.clone();
                thread::spawn(move || {
                    let mut s = s;
                    let (mut got, mut buf) = (Vec::new(), [0u8; 65536]);
                    let recs = loop {
                        let (recs, _) = records(&got);
                        if recs.iter().map(|(_, p)| p.len()).sum::<usize>() >= hello_len - 5 {
                            break recs.len();
                        }
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                    };
                    let _ = tx.send(recs);
                    if recs > 1 {
                        let _ = s.write_all(&DECODE_ERROR);
                        return;
                    }
                    let _ = s.write_all(&SERVER_HELLO);
                    while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
                });
            }
        });
        (port, rx)
    }

    fn read_exact_n(c: &mut TcpStream, n: usize) -> Vec<u8> {
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut b = vec![0u8; n];
        c.read_exact(&mut b).expect("reply from server");
        b
    }

    fn proxy(resolve: ResolveFn, strategy: Option<Strategy>) -> FragProxy {
        FragProxy::start(0, resolve, strategy, Arc::new(|_| {})).unwrap()
    }

    fn local() -> ResolveFn {
        Arc::new(|_| Ok(IpAddr::from([127, 0, 0, 1])))
    }

    /// Read upstream data until `done` says enough arrived.
    fn collect(rx: &mpsc::Receiver<Vec<u8>>, done: impl Fn(&[u8]) -> bool) -> (Vec<u8>, usize) {
        let (mut all, mut reads) = (Vec::new(), 0);
        while !done(&all) {
            all.extend(rx.recv_timeout(Duration::from_secs(3)).expect("upstream data"));
            reads += 1;
        }
        (all, reads)
    }

    fn reply_head(c: &mut TcpStream) -> String {
        let mut got = Vec::new();
        let mut b = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") && c.read(&mut b).unwrap_or(0) == 1 {
            got.push(b[0]);
        }
        String::from_utf8_lossy(&got).into_owned()
    }

    #[test]
    fn parse_head_waits_for_a_full_head() {
        assert!(parse_head(b"CONNECT a:443 HTTP/1.1\r\nHost: a").unwrap().is_none());
        let h = parse_head(b"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\nXYZ").unwrap().unwrap();
        assert_eq!((h.method.as_str(), h.target.as_str()), ("CONNECT", "a:443"));
        assert_eq!(h.rest, b"XYZ");
        assert!(parse_head(b"BROKEN\r\n\r\n").is_err());
    }

    #[test]
    fn split_host_port_handles_names_ports_and_ipv6() {
        assert_eq!(split_host_port("example.com:8443", 443).unwrap(), ("example.com".into(), 8443));
        assert_eq!(split_host_port("example.com", 443).unwrap(), ("example.com".into(), 443));
        assert_eq!(split_host_port("[::1]:443", 443).unwrap(), ("::1".into(), 443));
        assert!(split_host_port(":80", 80).is_err());
    }

    #[test]
    fn tunnel_splits_the_client_hello_and_passes_the_rest() {
        let (up_port, rx) = upstream();
        let p = proxy(local(), Some(Strategy::sni()));
        let mut c = TcpStream::connect(("127.0.0.1", p.port())).unwrap();
        c.write_all(format!("CONNECT store.steampowered.com:{up_port} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
        assert!(reply_head(&mut c).starts_with("HTTP/1.1 200"));

        let hello = sample_client_hello("store.steampowered.com");
        c.write_all(&hello).unwrap();
        let (got, reads) = collect(&rx, |b| b.len() >= hello.len() + 5);
        let (recs, _) = records(&got);
        assert_eq!(recs.len(), 2, "ClientHello arrives as two records");
        let payload: Vec<u8> = recs.into_iter().flat_map(|(_, p)| p).collect();
        assert_eq!(payload, hello[5..]);
        assert!(reads >= 2, "and in at least two TCP reads");
        assert_eq!(p.stats().fragmented, 1);

        c.write_all(b"after").unwrap();
        collect(&rx, |b| b.ends_with(b"after"));
        p.stop();
    }

    #[test]
    fn server_that_rejects_a_record_split_gets_a_tcp_split_instead() {
        let hello = sample_client_hello("id.plaync.com");
        let (up_port, rx) = picky_upstream(hello.len());
        let log = Arc::new(Mutex::new(Vec::<String>::new()));
        let p = {
            let log = log.clone();
            FragProxy::start(0, local(), Some(Strategy::sni()), Arc::new(move |m| log.lock().unwrap().push(m))).unwrap()
        };

        for round in 0..2 {
            let mut c = TcpStream::connect(("127.0.0.1", p.port())).unwrap();
            c.write_all(format!("CONNECT id.plaync.com:{up_port} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
            assert!(reply_head(&mut c).starts_with("HTTP/1.1 200"));
            c.write_all(&hello).unwrap();
            assert_eq!(read_exact_n(&mut c, SERVER_HELLO.len()), SERVER_HELLO, "round {round}: client sees the server's answer, not the alert");
            if round == 0 {
                assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), 2, "first try: record split");
            }
            assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), 1, "round {round}: one record, split only across TCP");
        }
        assert!(rx.try_recv().is_err(), "the second connection went straight to the remembered split");
        let log = log.lock().unwrap().join("\n");
        assert!(log.contains("rejected record split") && log.contains("using TCP split"), "{log}");
        p.stop();
    }

    #[test]
    fn plain_http_is_rewritten_to_origin_form() {
        let (up_port, rx) = upstream();
        let p = proxy(local(), Some(Strategy::sni()));
        let mut c = TcpStream::connect(("127.0.0.1", p.port())).unwrap();
        c.write_all(
            format!("GET http://example.test:{up_port}/a?b=1 HTTP/1.1\r\nHost: example.test\r\nProxy-Connection: keep-alive\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
        let (got, _) = collect(&rx, |b| b.windows(4).any(|w| w == b"\r\n\r\n"));
        let head = String::from_utf8_lossy(&got);
        assert!(head.starts_with("GET /a?b=1 HTTP/1.1\r\n"), "{head}");
        assert!(!head.to_ascii_lowercase().contains("proxy-connection"));
        assert!(head.contains("Connection: close"));
        p.stop();
    }

    #[test]
    fn upstream_failure_answers_502() {
        let p = proxy(Arc::new(|_| Err(io::Error::new(io::ErrorKind::NotFound, "no such host"))), None);
        let mut c = TcpStream::connect(("127.0.0.1", p.port())).unwrap();
        c.write_all(b"CONNECT nowhere.invalid:443 HTTP/1.1\r\n\r\n").unwrap();
        assert!(reply_head(&mut c).starts_with("HTTP/1.1 502"));
        assert_eq!(p.stats().errors, 1);
        p.stop();
    }
}
