//! TLS ClientHello helpers: detect a ClientHello, locate its SNI host name, and
//! split it so that name-based (SNI) filters cannot read the host from a single
//! packet. Servers must accept a handshake spread over several records
//! (RFC 8446 §5.1), so the split is invisible to the far end.

use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::time::Duration;

const RECORD_HEADER: usize = 5;

/// Pause between the two halves so the kernel sends them as separate segments.
pub const GAP: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Split in the middle of the SNI host name.
    Sni,
    /// Split `n` bytes into the record payload.
    Bytes,
}

/// Serialized the same way as the Electron build: `{kind:"sni"}`,
/// `{kind:"bytes",n:1}`, `{kind:"sni",record:false}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Strategy {
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<usize>,
    /// `Some(false)`: keep one record and only split it across TCP segments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<bool>,
}

impl Strategy {
    pub const fn sni() -> Self {
        Self { kind: Kind::Sni, n: None, record: None }
    }
    const fn bytes(n: usize) -> Self {
        Self { kind: Kind::Bytes, n: Some(n), record: None }
    }
}

/// Tried in this order when measuring which one a network lets through.
pub fn strategies() -> Vec<Strategy> {
    vec![
        Strategy::sni(),
        Strategy::bytes(1),
        Strategy::bytes(3),
        Strategy::bytes(40),
        Strategy { kind: Kind::Sni, n: None, record: Some(false) },
    ]
}

pub fn describe(s: Option<&Strategy>) -> String {
    let Some(s) = s else { return "none".into() };
    let where_ = match s.kind {
        Kind::Sni => "mid host name".to_string(),
        Kind::Bytes => {
            let n = s.n.unwrap_or(1);
            format!("after {n} byte{}", if n == 1 { "" } else { "s" })
        }
    };
    if s.record == Some(false) {
        format!("TCP split {where_}")
    } else {
        format!("record split {where_}")
    }
}

pub fn is_client_hello(buf: &[u8]) -> bool {
    buf.len() > RECORD_HEADER
        && buf[0] == 0x16 // handshake record
        && buf[1] == 0x03 // TLS 1.x record version
        && buf[5] == 0x01 // handshake type: client_hello
}

/// Total bytes of the first record (header + payload), or 0 if unknown.
pub fn record_length(buf: &[u8]) -> usize {
    if buf.len() >= RECORD_HEADER {
        RECORD_HEADER + u16::from_be_bytes([buf[3], buf[4]]) as usize
    } else {
        0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Sni {
    pub offset: usize,
    pub length: usize,
    pub host: String,
}

/// Locate the server_name host inside a ClientHello.
pub fn find_sni(buf: &[u8]) -> Option<Sni> {
    if !is_client_hello(buf) {
        return None;
    }
    let be16 = |p: usize| -> Option<usize> {
        Some(u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]) as usize)
    };
    let mut p = RECORD_HEADER + 4 + 2 + 32; // headers + client_version + random
    p += 1 + *buf.get(p)? as usize; // session_id
    p += 2 + be16(p)?; // cipher_suites
    p += 1 + *buf.get(p)? as usize; // compression_methods
    let ext_end = buf.len().min(p + 2 + be16(p)?);
    p += 2;
    while p + 4 <= ext_end {
        let typ = be16(p)?;
        let len = be16(p + 2)?;
        let body = p + 4;
        if typ == 0x0000 {
            // server_name_list length (2), name_type (1), host_name length (2), host_name
            if body + 5 > ext_end || buf[body + 2] != 0x00 {
                return None;
            }
            let length = be16(body + 3)?;
            let offset = body + 5;
            if offset + length > ext_end {
                return None;
            }
            let host = String::from_utf8_lossy(&buf[offset..offset + length]).into_owned();
            return Some(Sni { offset, length, host });
        }
        p = body + len;
    }
    None
}

/// Split the first record at absolute offset `at` into two well-formed records.
pub fn split_record(buf: &[u8], at: usize) -> Vec<Vec<u8>> {
    let end = record_length(buf);
    if at <= RECORD_HEADER || at >= end || end > buf.len() {
        return vec![buf.to_vec()];
    }
    let header = |len: usize| [buf[0], buf[1], buf[2], (len >> 8) as u8, len as u8];
    let (a, b) = (&buf[RECORD_HEADER..at], &buf[at..end]);
    let mut first = header(a.len()).to_vec();
    first.extend_from_slice(a);
    let mut second = header(b.len()).to_vec();
    second.extend_from_slice(b);
    second.extend_from_slice(&buf[end..]);
    vec![first, second]
}

/// The chunks to write as separate TCP segments. Non-ClientHello data passes through.
pub fn fragment(buf: &[u8], strategy: Option<&Strategy>) -> Vec<Vec<u8>> {
    let whole = || vec![buf.to_vec()];
    let Some(s) = strategy else { return whole() };
    if !is_client_hello(buf) {
        return whole();
    }
    let at = match s.kind {
        Kind::Sni => match find_sni(buf) {
            Some(sni) => sni.offset + (sni.length / 2).max(1),
            None => return whole(),
        },
        Kind::Bytes => RECORD_HEADER + s.n.unwrap_or(1),
    };
    if s.record == Some(false) {
        return if at > 0 && at < buf.len() {
            vec![buf[..at].to_vec(), buf[at..].to_vec()]
        } else {
            whole()
        };
    }
    split_record(buf, at)
}

/// Write each chunk, flushing and pausing between them so they are not coalesced.
/// The caller sets TCP_NODELAY on the socket.
pub fn write_chunks<W: Write>(w: &mut W, chunks: &[Vec<u8>], gap: Duration) -> io::Result<()> {
    for (i, chunk) in chunks.iter().enumerate() {
        w.write_all(chunk)?;
        w.flush()?;
        if i + 1 < chunks.len() {
            std::thread::sleep(gap);
        }
    }
    Ok(())
}

/// A fresh ClientHello, as rustls would send it to `host`.
pub fn client_hello(host: &str) -> Option<Vec<u8>> {
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).ok()?;
    let mut conn = rustls::ClientConnection::new(crate::probe::client_config(), name).ok()?;
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).ok()?;
    }
    Some(out)
}

#[cfg(test)]
pub fn sample_client_hello(host: &str) -> Vec<u8> {
    client_hello(host).unwrap()
}

/// Parse a byte stream into (content type, payload) TLS records.
#[cfg(test)]
pub fn records(buf: &[u8]) -> (Vec<(u8, Vec<u8>)>, usize) {
    let mut out = Vec::new();
    let mut p = 0;
    while p + RECORD_HEADER <= buf.len() {
        let len = u16::from_be_bytes([buf[p + 3], buf[p + 4]]) as usize;
        let end = (p + RECORD_HEADER + len).min(buf.len());
        out.push((buf[p], buf[p + RECORD_HEADER..end].to_vec()));
        p += RECORD_HEADER + len;
    }
    (out, buf.len().saturating_sub(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "store.steampowered.com";

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn finds_sni_in_a_real_client_hello() {
        let hello = sample_client_hello(HOST);
        assert!(is_client_hello(&hello));
        let sni = find_sni(&hello).unwrap();
        assert_eq!(sni.host, HOST);
        assert_eq!(&hello[sni.offset..sni.offset + sni.length], HOST.as_bytes());
    }

    #[test]
    fn passes_other_data_through() {
        let http = b"GET / HTTP/1.1\r\n\r\n";
        assert!(!is_client_hello(http));
        assert_eq!(fragment(http, Some(&Strategy::sni())), vec![http.to_vec()]);
    }

    #[test]
    fn every_strategy_keeps_the_handshake_intact() {
        let hello = sample_client_hello(HOST);
        for s in strategies() {
            let parts = fragment(&hello, Some(&s));
            assert_eq!(parts.len(), 2, "{s:?} splits into two writes");
            let joined: Vec<u8> = parts.concat();
            if s.record == Some(false) {
                assert_eq!(joined, hello, "{s:?} must not change bytes");
            } else {
                let (recs, trailing) = records(&joined);
                assert_eq!(trailing, 0);
                assert_eq!(recs.len(), 2, "{s:?} gives two records");
                assert!(recs.iter().all(|(t, _)| *t == 0x16));
                let payload: Vec<u8> = recs.into_iter().flat_map(|(_, p)| p).collect();
                assert_eq!(payload, hello[5..], "{s:?} keeps the payload");
            }
            if s.kind == Kind::Sni {
                for p in &parts {
                    assert!(!contains(p, HOST.as_bytes()), "{s:?} hides the whole host name");
                }
            }
        }
    }

    #[test]
    fn sni_split_lands_inside_the_host_name() {
        let hello = sample_client_hello(HOST);
        let parts = fragment(&hello, Some(&Strategy::sni()));
        assert!(contains(&parts[0], b"store.stea"));
        assert!(contains(&parts[1], b"powered.com"));
    }

    #[test]
    fn strategy_json_matches_the_ui() {
        let json: Vec<String> = strategies().iter().map(|s| serde_json::to_string(s).unwrap()).collect();
        assert_eq!(json[0], r#"{"kind":"sni"}"#);
        assert_eq!(json[1], r#"{"kind":"bytes","n":1}"#);
        assert_eq!(json[4], r#"{"kind":"sni","record":false}"#);
        assert_eq!(describe(Some(&strategies()[2])), "record split after 3 bytes");
        assert_eq!(describe(None), "none");
    }
}
