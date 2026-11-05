'use strict';
// TLS ClientHello helpers: detect a ClientHello, locate its SNI host name, and
// split it so that name-based (SNI) filters cannot read the host from a single
// packet. Servers must accept a handshake spread over several records
// (RFC 8446 §5.1), so the split is invisible to the far end.

const { Duplex } = require('stream');

const RECORD_HEADER = 5;

function isClientHello(buf) {
  return buf.length > RECORD_HEADER &&
    buf[0] === 0x16 && // handshake record
    buf[1] === 0x03 && // TLS 1.x record version
    buf[5] === 0x01;   // handshake type: client_hello
}

// Total bytes of the first record (header + payload), or 0 if unknown.
function recordLength(buf) {
  return buf.length >= RECORD_HEADER ? RECORD_HEADER + buf.readUInt16BE(3) : 0;
}

// Returns { offset, length, host } of the server_name host inside buf, or null.
function findSni(buf) {
  if (!isClientHello(buf)) return null;
  let p = RECORD_HEADER + 4; // record header + handshake type/length
  p += 2 + 32;               // client_version + random
  if (p >= buf.length) return null;
  p += 1 + buf[p];           // session_id
  if (p + 2 > buf.length) return null;
  p += 2 + buf.readUInt16BE(p); // cipher_suites
  if (p >= buf.length) return null;
  p += 1 + buf[p];           // compression_methods
  if (p + 2 > buf.length) return null;
  const extEnd = Math.min(buf.length, p + 2 + buf.readUInt16BE(p));
  p += 2;
  while (p + 4 <= extEnd) {
    const type = buf.readUInt16BE(p);
    const len = buf.readUInt16BE(p + 2);
    const body = p + 4;
    if (type === 0x0000) {
      // server_name_list length (2), name_type (1), host_name length (2), host_name
      if (body + 5 > extEnd || buf[body + 2] !== 0x00) return null;
      const length = buf.readUInt16BE(body + 3);
      const offset = body + 5;
      if (offset + length > extEnd) return null;
      return { offset, length, host: buf.toString('ascii', offset, offset + length) };
    }
    p = body + len;
  }
  return null;
}

// Split the first record at absolute offset `at` into two well-formed records.
function splitRecord(buf, at) {
  const end = recordLength(buf);
  if (at <= RECORD_HEADER || at >= end) return [buf];
  const header = (len) => Buffer.from([buf[0], buf[1], buf[2], len >> 8, len & 0xff]);
  const a = buf.subarray(RECORD_HEADER, at);
  const b = buf.subarray(at, end);
  return [Buffer.concat([header(a.length), a]), Buffer.concat([header(b.length), b, buf.subarray(end)])];
}

// Strategies, tried in this order when measuring which one a network lets through:
//   { kind: 'sni' }                 split record mid-host-name and send as two TCP segments
//   { kind: 'bytes', n }            split record n bytes into the payload
//   { kind: 'sni', record: false }  keep one record, only split it across TCP segments
const STRATEGIES = [
  { kind: 'sni' },
  { kind: 'bytes', n: 1 },
  { kind: 'bytes', n: 3 },
  { kind: 'bytes', n: 40 },
  { kind: 'sni', record: false },
];

function describeStrategy(s) {
  if (!s) return 'none';
  const where = s.kind === 'sni' ? 'mid host name' : `after ${s.n} byte${s.n === 1 ? '' : 's'}`;
  return s.record === false ? `TCP split ${where}` : `record split ${where}`;
}

// Returns the chunks to write as separate TCP segments. Non-ClientHello data passes through.
function fragment(buf, strategy) {
  if (!strategy || !isClientHello(buf)) return [buf];
  let at;
  if (strategy.kind === 'sni') {
    const sni = findSni(buf);
    if (!sni) return [buf];
    at = sni.offset + Math.max(1, Math.floor(sni.length / 2));
  } else {
    at = RECORD_HEADER + strategy.n;
  }
  if (strategy.record === false) {
    return at > 0 && at < buf.length ? [buf.subarray(0, at), buf.subarray(at)] : [buf];
  }
  return splitRecord(buf, at);
}

// Write chunks one at a time, waiting for each to flush plus a short gap, so the
// kernel sends them as separate segments instead of coalescing them.
function writeChunks(socket, chunks, gapMs = 10) {
  socket.setNoDelay?.(true);
  return chunks.reduce((prev, chunk, i) => prev.then(() => new Promise((resolve, reject) => {
    socket.write(chunk, (err) => {
      if (err) return reject(err);
      if (i === chunks.length - 1) return resolve();
      setTimeout(resolve, gapMs);
    });
  })), Promise.resolve());
}

// Wrap a raw TCP socket so its first write (the ClientHello from tls.connect) is fragmented.
function fragmentingDuplex(raw, strategy) {
  let first = true;
  const d = new Duplex({
    write(chunk, _enc, cb) {
      if (!first) return raw.write(chunk, cb);
      first = false;
      writeChunks(raw, fragment(chunk, strategy)).then(() => cb(), cb);
    },
    read() { raw.resume(); },
    final(cb) { raw.end(); cb(); },
    destroy(err, cb) { raw.destroy(); cb(err); },
  });
  raw.on('data', (c) => { if (!d.push(c)) raw.pause(); });
  raw.on('end', () => d.push(null));
  raw.on('error', (e) => d.destroy(e));
  return d;
}

module.exports = {
  isClientHello, recordLength, findSni, splitRecord, fragment, writeChunks,
  fragmentingDuplex, STRATEGIES, describeStrategy,
};
