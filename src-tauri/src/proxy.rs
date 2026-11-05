//! Local HTTP proxy that splits each TLS ClientHello it forwards.
//!
//! RevoltWarp does this in the kernel with WinDivert, which catches every app but
//! needs a driver. A proxy needs nothing installed and covers every app that uses
//! the system proxy setting; apps that ignore it are not covered.

use crate::tls::{client_hello, describe, fragment, is_client_hello, record_length, write_chunks, Strategy, GAP};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
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
/// How long to wait for the server's answer to a ClientHello before trying the
/// next plan. Servers answer within one round trip; a filter that drops packets,
/// or a server that hangs on a split hello (login.live.com), never answers.
const FIRST_REPLY_WAIT: Duration = if cfg!(test) { Duration::from_millis(500) } else { Duration::from_secs(5) };
const ALERT: u8 = 0x15;

pub type ResolveFn = Arc<dyn Fn(&str) -> io::Result<IpAddr> + Send + Sync>;
pub type LogFn = Arc<dyn Fn(String) + Send + Sync>;
/// "host:port" -> the split that host needs (`None`: no split).
pub type Learned = HashMap<String, Option<Strategy>>;
/// Called with the main strategy and everything learned, each time it changes.
pub type LearnFn = Arc<dyn Fn(Option<&Strategy>, &Learned) + Send + Sync>;

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
    fallback: Mutex<Learned>,
    /// Hosts a probe found reachable without a split (this session only).
    unblocked: Mutex<HashSet<String>>,
    /// One probe per new host at a time; other connections wait for its result.
    probing: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    on_learn: RwLock<Option<LearnFn>>,
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
            unblocked: Mutex::new(HashSet::new()),
            probing: Mutex::new(HashMap::new()),
            on_learn: RwLock::new(None),
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
        self.ctx.unblocked.lock().unwrap().clear();
        self.ctx.learned_changed();
    }

    /// Start from splits learned earlier (a previous session, the connection
    /// check), so the first connection to a blocked host doesn't go out unsplit.
    pub fn learn(&self, hosts: Learned) {
        if hosts.is_empty() {
            return;
        }
        self.ctx.fallback.lock().unwrap().extend(hosts);
        self.ctx.learned_changed();
    }

    pub fn on_learn(&self, f: LearnFn) {
        *self.ctx.on_learn.write().unwrap() = Some(f);
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

    /// CONNECT host:443: answer 200, then forward the first ClientHello, split only
    /// if the host needs it.
    ///
    /// Splitting is not free. Some servers break on a ClientHello spread over two
    /// TLS records, although RFC 8446 requires them to accept it: plaync.com
    /// answers decode_error or resets, login.live.com never answers, and xbox.com
    /// cannot read the host name and serves the wrong certificate, which the proxy
    /// cannot see (TLS 1.3 encrypts it). So the hello goes out unsplit first, and
    /// only when the server fails to answer it (reset, close, alert, silence) does
    /// the proxy reconnect and resend it split. The browser has received nothing
    /// from the server yet, so a retry is invisible to it. The plan that worked is
    /// remembered per host and tried first next time, so a blocked host costs one
    /// failed try per session. It is only a starting point: a split that got
    /// through once by luck (a filter that drops most TCP splits) falls back to
    /// the stronger plans after it instead of failing every later connection.
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
        let plans = self.plans_for_host(&key, &host, port, &hello);
        for (i, plan) in plans.iter().enumerate() {
            if i > 0 {
                up = self.connect_upstream(&host, port)?;
            }
            let ip = up.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
            let chunks = fragment(&hello, plan.as_ref());
            if chunks.len() > 1 {
                self.stats.fragmented.fetch_add(1, Relaxed);
            }
            write_chunks(&mut up, &chunks, GAP).map_err(|e| e.to_string())?;
            if plans.len() == 1 {
                return Ok((up, Vec::new()));
            }
            let (failure, reply) = first_reply(&mut up);
            let rejected = failure.is_some();
            if let Some(why) = &failure {
                let next = if i + 1 < plans.len() { "retrying" } else { "giving up" };
                (self.log)(format!("{key}: {} failed ({why}), {next} [{ip}]", label(plan.as_ref())));
                if i + 1 < plans.len() {
                    continue;
                }
            }
            if i > 0 && !rejected {
                (self.log)(format!("{key}: using {}", label(plan.as_ref())));
                self.fallback.lock().unwrap().insert(key, plan.clone());
                self.learned_changed();
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

    /// The plans to try for this connection, starting with the one known to work.
    ///
    /// A filter that has seen a ClientHello unsplit often still resets it when it
    /// is resent split (about 4 in 10 on Steam's CDNs; never with a fresh hello).
    /// The proxy can only resend the browser's hello, so for a host it knows
    /// nothing about it first probes with throwaway hellos of its own: unsplit,
    /// then each split, and the browser's hello goes out once in the form that
    /// got through. A host that needs a split is remembered (and saved); one that
    /// doesn't is remembered for the session.
    fn plans_for_host(&self, key: &str, host: &str, port: u16, hello: &[u8]) -> Vec<Option<Strategy>> {
        let mut plans = plans_for(hello, self.strategy.read().unwrap().clone());
        if plans.len() == 1 {
            return plans;
        }
        let known = |ctx: &Self| -> Option<usize> {
            if ctx.unblocked.lock().unwrap().contains(key) {
                return Some(0);
            }
            let remembered = ctx.fallback.lock().unwrap().get(key).cloned()?;
            Some(plans.iter().position(|p| *p == remembered).unwrap_or(0))
        };
        let start = known(self).or_else(|| {
            let gate = self.probing.lock().unwrap().entry(key.to_string()).or_default().clone();
            let _one_at_a_time = gate.lock().unwrap();
            known(self).or_else(|| self.probe(key, host, port, &plans))
        });
        plans.drain(..start.unwrap_or(0));
        plans
    }

    /// Index of the first plan a fresh hello gets through with, remembered.
    fn probe(&self, key: &str, host: &str, port: u16, plans: &[Option<Strategy>]) -> Option<usize> {
        let works = |plan: &Option<Strategy>| -> bool {
            let (Some(hello), Ok(mut up)) = (client_hello(host), self.connect_upstream(host, port)) else { return false };
            write_chunks(&mut up, &fragment(&hello, plan.as_ref()), GAP).is_ok() && first_reply(&mut up).0.is_none()
        };
        let Some(i) = plans.iter().position(works) else {
            (self.log)(format!("{key}: probe found no working split"));
            return None;
        };
        if i == 0 {
            self.unblocked.lock().unwrap().insert(key.to_string());
        } else {
            (self.log)(format!("{key}: blocked by host name, using {}", label(plans[i].as_ref())));
            self.fallback.lock().unwrap().insert(key.to_string(), plans[i].clone());
            self.learned_changed();
        }
        Some(i)
    }

    fn learned_changed(&self) {
        let Some(f) = self.on_learn.read().unwrap().clone() else { return };
        let learned = self.fallback.lock().unwrap().clone();
        f(self.strategy.read().unwrap().as_ref(), &learned);
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

fn label(plan: Option<&Strategy>) -> String {
    match plan {
        Some(s) => describe(Some(s)),
        None => "no split".into(),
    }
}

/// The proxy plan matching a split the connection check found working, for a
/// proxy whose main strategy is `main`. Same split point as the proxy uses, kept
/// as a TCP-only split if that is what the check needed.
pub fn plan_for_check(main: Option<&Strategy>, found: &Strategy) -> Option<Strategy> {
    let main = main?.clone();
    Some(if found.record == Some(false) { Strategy { record: Some(false), ..main } } else { Strategy { record: None, ..main } })
}

/// What to try, in order, for one ClientHello, safest first: unsplit; then the
/// chosen split point as a TCP-only split, which keeps one TLS record so every
/// server reads it like an unsplit hello; then as a record split, which gets past
/// filters that reassemble TCP but which some servers mishandle (see open_tunnel).
fn plans_for(hello: &[u8], main: Option<Strategy>) -> Vec<Option<Strategy>> {
    match main {
        Some(s) if is_client_hello(hello) => {
            let tcp = Strategy { record: Some(false), ..s.clone() };
            let record = Strategy { record: None, ..s };
            vec![None, Some(tcp), Some(record)]
        }
        _ => vec![None],
    }
}

/// Wait for the server's first answer. Returns why it failed when it is a TLS
/// alert, the server closed or reset the connection, or it said nothing for
/// FIRST_REPLY_WAIT; the client's bytes meanwhile wait in its socket buffer.
/// The bytes read are returned either way.
fn first_reply(up: &mut TcpStream) -> (Option<String>, Vec<u8>) {
    let _ = up.set_read_timeout(Some(FIRST_REPLY_WAIT));
    let mut buf = vec![0u8; 16 * 1024];
    let result = match up.read(&mut buf) {
        Ok(0) => (Some("closed".into()), Vec::new()),
        Ok(n) if buf[0] == ALERT => {
            let desc = if n >= 7 { format!("alert {}", buf[6]) } else { "alert".into() };
            (Some(desc), buf[..n].to_vec())
        }
        Ok(n) => (None, buf[..n].to_vec()),
        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
            (Some("no answer".into()), Vec::new())
        }
        Err(e) => (Some(format!("{:?}", e.kind())), Vec::new()),
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

    /// Fake upstream for plain HTTP: reports every read it gets.
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
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (port, rx)
    }

    #[derive(Clone, Copy)]
    struct Server {
        /// Like an SNI filter: drop the connection when the host name is seen
        /// whole, in one TCP read or, with `reassembles`, anywhere in the stream
        /// (only a record split breaks it up then). `silent`: stop answering
        /// instead of closing, as a packet drop would.
        filter: bool,
        reassembles: bool,
        silent: bool,
        /// Like id.plaync.com: answer decode_error to a hello in several records.
        picky: bool,
    }

    const OPEN: Server = Server { filter: false, reassembles: false, silent: false, picky: false };

    /// How one connection's ClientHello arrived and whether it was answered.
    #[derive(Debug, PartialEq)]
    struct Seen {
        records: usize,
        accepted: bool,
    }

    /// Fake TLS server. Answers an accepted ClientHello with SERVER_HELLO, then
    /// echoes everything back. Reports a `Seen` per connection.
    fn tls_server(hello_len: usize, host: &'static str, how: Server) -> (u16, mpsc::Receiver<Seen>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                let tx = tx.clone();
                thread::spawn(move || {
                    let mut s = s;
                    let (mut got, mut buf, mut whole_host) = (Vec::new(), [0u8; 65536], false);
                    let records = loop {
                        let (recs, _) = records(&got);
                        if recs.iter().map(|(_, p)| p.len()).sum::<usize>() >= hello_len - 5 {
                            break recs.len();
                        }
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                whole_host |= buf[..n].windows(host.len()).any(|w| w == host.as_bytes());
                                got.extend_from_slice(&buf[..n]);
                            }
                        }
                    };
                    whole_host |= how.reassembles && got.windows(host.len()).any(|w| w == host.as_bytes());
                    let filtered = how.filter && whole_host;
                    let accepted = !filtered && !(how.picky && records > 1);
                    let _ = tx.send(Seen { records, accepted });
                    if filtered {
                        if how.silent {
                            while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
                        }
                        return;
                    }
                    if !accepted {
                        let _ = s.write_all(&DECODE_ERROR);
                        return;
                    }
                    let _ = s.write_all(&SERVER_HELLO);
                    while let Ok(n) = s.read(&mut buf) {
                        if n == 0 || s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (port, rx)
    }

    /// Open a tunnel to `host` through the proxy, send its ClientHello, and check
    /// that the client sees the server's answer and that data then flows both ways.
    fn tunnel(p: &FragProxy, host: &str, up_port: u16, hello: &[u8]) {
        let mut c = TcpStream::connect(("127.0.0.1", p.port())).unwrap();
        c.write_all(format!("CONNECT {host}:{up_port} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
        assert!(reply_head(&mut c).starts_with("HTTP/1.1 200"));
        c.write_all(hello).unwrap();
        assert_eq!(read_exact_n(&mut c, SERVER_HELLO.len()), SERVER_HELLO, "client sees the server's answer");
        c.write_all(b"after").unwrap();
        assert_eq!(read_exact_n(&mut c, 5), b"after");
    }

    fn seen(rx: &mpsc::Receiver<Seen>) -> Vec<Seen> {
        let mut out = Vec::new();
        while let Ok(s) = rx.recv_timeout(Duration::from_millis(200)) {
            out.push(s);
        }
        out
    }

    fn logging_proxy(strategy: Option<Strategy>) -> (FragProxy, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        let p = FragProxy::start(0, local(), strategy, Arc::new(move |m| sink.lock().unwrap().push(m))).unwrap();
        (p, log)
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
    fn unblocked_host_gets_the_hello_unsplit() {
        let hello = sample_client_hello("www.xbox.com");
        let (up_port, rx) = tls_server(hello.len(), "www.xbox.com", OPEN);
        let p = proxy(local(), Some(Strategy::sni()));
        tunnel(&p, "www.xbox.com", up_port, &hello);
        assert_eq!(seen(&rx), [Seen { records: 1, accepted: true }, Seen { records: 1, accepted: true }], "probe, then the browser's hello, both unsplit");
        tunnel(&p, "www.xbox.com", up_port, &hello);
        assert_eq!(seen(&rx), [Seen { records: 1, accepted: true }], "no second probe");
        assert_eq!(p.stats().fragmented, 0);
        p.stop();
    }

    const STEAM: &str = "store.steampowered.com";
    const NO: Seen = Seen { records: 1, accepted: false };

    #[test]
    fn a_probe_finds_the_tcp_split_and_the_browser_hello_is_sent_once() {
        let hello = sample_client_hello(STEAM);
        let (up_port, rx) = tls_server(hello.len(), STEAM, Server { filter: true, ..OPEN });
        let (p, log) = logging_proxy(Some(Strategy::sni()));

        tunnel(&p, STEAM, up_port, &hello);
        assert_eq!(seen(&rx), [NO, Seen { records: 1, accepted: true }, Seen { records: 1, accepted: true }], "probes: unsplit filtered, TCP split passes; then the browser's hello");
        tunnel(&p, STEAM, up_port, &hello);
        assert_eq!(seen(&rx), [Seen { records: 1, accepted: true }], "second time: straight to the TCP split");
        assert_eq!(p.stats().fragmented, 2);
        assert!(log.lock().unwrap().iter().any(|m| m.ends_with("blocked by host name, using TCP split mid host name")));
        p.stop();
    }

    #[test]
    fn a_filter_that_reassembles_tcp_needs_the_record_split() {
        let hello = sample_client_hello(STEAM);
        let filter = Server { filter: true, reassembles: true, ..OPEN };
        let (up_port, rx) = tls_server(hello.len(), STEAM, filter);
        let (p, log) = logging_proxy(Some(Strategy::sni()));

        tunnel(&p, STEAM, up_port, &hello);
        assert_eq!(seen(&rx), [NO, NO, Seen { records: 2, accepted: true }, Seen { records: 2, accepted: true }], "the browser's hello is only sent split");
        tunnel(&p, STEAM, up_port, &hello);
        assert_eq!(seen(&rx), [Seen { records: 2, accepted: true }]);
        assert!(log.lock().unwrap().iter().any(|m| m.ends_with("using record split mid host name")));

        p.set_strategy(Some(Strategy::sni()));
        tunnel(&p, STEAM, up_port, &hello);
        assert_eq!(seen(&rx).len(), 4, "changing the strategy forgets what was learned");
        p.stop();
    }

    #[test]
    fn a_remembered_split_that_stops_working_falls_back_to_the_next_plan() {
        let hello = sample_client_hello(STEAM);
        // Learned the TCP split earlier, but the filter now catches it.
        let (up_port, rx) = tls_server(hello.len(), STEAM, Server { filter: true, reassembles: true, ..OPEN });
        let (p, log) = logging_proxy(Some(Strategy::sni()));
        let tcp = Strategy { record: Some(false), ..Strategy::sni() };
        p.learn(HashMap::from([(format!("{STEAM}:{up_port}"), Some(tcp))]));

        tunnel(&p, STEAM, up_port, &hello);
        assert_eq!(seen(&rx), [NO, Seen { records: 2, accepted: true }], "learned split fails, record split works");
        tunnel(&p, STEAM, up_port, &hello);
        assert_eq!(seen(&rx), [Seen { records: 2, accepted: true }], "record split is now remembered");
        assert!(log.lock().unwrap().iter().any(|m| m.ends_with("using record split mid host name")));
        p.stop();
    }

    #[test]
    fn a_learned_host_skips_the_unsplit_try_and_new_lessons_are_reported() {
        let hello = sample_client_hello(STEAM);
        let filter = Server { filter: true, reassembles: true, ..OPEN };
        let (up_port, rx) = tls_server(hello.len(), STEAM, filter);
        let (p, _) = logging_proxy(Some(Strategy::sni()));
        let reported = Arc::new(Mutex::new(Vec::<Learned>::new()));
        let sink = reported.clone();
        p.on_learn(Arc::new(move |_, l| sink.lock().unwrap().push(l.clone())));

        let key = format!("{STEAM}:{up_port}");
        p.learn(HashMap::from([(key.clone(), plan_for_check(Some(&Strategy::sni()), &Strategy::sni()))]));
        tunnel(&p, STEAM, up_port, &hello);
        assert_eq!(seen(&rx), [Seen { records: 2, accepted: true }], "first connection goes straight to the record split");
        assert_eq!(reported.lock().unwrap().last().unwrap()[&key], Some(Strategy::sni()));
        p.stop();
    }

    #[test]
    fn a_filter_that_drops_silently_is_detected_by_timeout() {
        let hello = sample_client_hello(STEAM);
        let (up_port, rx) = tls_server(hello.len(), STEAM, Server { filter: true, silent: true, ..OPEN });
        let (p, log) = logging_proxy(Some(Strategy::sni()));
        tunnel(&p, STEAM, up_port, &hello);
        assert_eq!(seen(&rx), [NO, Seen { records: 1, accepted: true }, Seen { records: 1, accepted: true }]);
        assert!(log.lock().unwrap().iter().any(|m| m.ends_with("blocked by host name, using TCP split mid host name")));
        p.stop();
    }

    #[test]
    fn when_every_plan_fails_the_client_gets_the_last_answer() {
        let host = "id.plaync.com";
        let hello = sample_client_hello(host);
        let all = Server { filter: true, reassembles: true, picky: true, ..OPEN };
        let (up_port, rx) = tls_server(hello.len(), host, all);
        let (p, log) = logging_proxy(Some(Strategy::sni()));
        let mut c = TcpStream::connect(("127.0.0.1", p.port())).unwrap();
        c.write_all(format!("CONNECT {host}:{up_port} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
        assert!(reply_head(&mut c).starts_with("HTTP/1.1 200"));
        c.write_all(&hello).unwrap();
        assert_eq!(read_exact_n(&mut c, DECODE_ERROR.len()), DECODE_ERROR, "the browser sees the server's alert");
        let rejected = Seen { records: 2, accepted: false };
        let rejected2 = Seen { records: 2, accepted: false };
        assert_eq!(seen(&rx), [NO, NO, rejected, NO, NO, rejected2], "probes, then the browser's hello every way");
        let log = log.lock().unwrap().join("\n");
        assert!(log.contains("record split mid host name failed (alert 50), giving up"), "{log}");
        assert!(!log.contains("using"), "nothing remembered: {log}");
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
