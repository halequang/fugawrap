'use strict';
const tls = require('tls');
const { Duplex } = require('stream');

// Capture the real ClientHello Node's TLS stack sends for `servername`.
function captureClientHello(servername) {
  return new Promise((resolve) => {
    const sink = new Duplex({
      write(chunk, _enc, cb) { resolve(Buffer.from(chunk)); cb(); },
      read() {},
    });
    const t = tls.connect({ socket: sink, servername });
    t.on('error', () => {});
    setTimeout(() => t.destroy(), 50);
  });
}

// Parse a byte stream into TLS records.
function records(buf) {
  const out = [];
  let p = 0;
  while (p + 5 <= buf.length) {
    const len = buf.readUInt16BE(p + 3);
    out.push({ type: buf[p], version: buf.readUInt16BE(p + 1), payload: buf.subarray(p + 5, p + 5 + len) });
    p += 5 + len;
  }
  return { records: out, trailing: buf.length - p };
}

module.exports = { captureClientHello, records };
