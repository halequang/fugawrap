'use strict';
// Local HTTP proxy that splits each TLS ClientHello it forwards.
//
// RevoltWarp does this in the kernel with WinDivert, which catches every app but
// needs a driver. A proxy needs nothing installed and covers every app that uses
// the Windows system proxy (browsers, Chromium-based clients such as Steam's web
// views); apps that ignore the system proxy are not covered.

const net = require('net');
const { EventEmitter } = require('events');
const { fragment, writeChunks, isClientHello, recordLength } = require('./tls');

const MAX_HEAD = 16 * 1024;
const HELLO_WAIT_MS = 1000;

// Parse a proxy request head. Returns null until the head is complete.
function parseHead(buf) {
  const end = buf.indexOf('\r\n\r\n');
  if (end < 0) return null;
  const head = buf.toString('latin1', 0, end);
  const [requestLine, ...headerLines] = head.split('\r\n');
  const [method, target, version] = requestLine.split(' ');
  if (!method || !target || !version) throw new Error('Malformed request line');
  return { method, target, version, headerLines, rest: buf.subarray(end + 4) };
}

function splitHostPort(s, defaultPort) {
  const m = /^\[([^\]]+)\](?::(\d+))?$/.exec(s) || /^([^:]+)(?::(\d+))?$/.exec(s);
  if (!m) throw new Error(`Bad host: ${s}`);
  return { host: m[1], port: Number(m[2] || defaultPort) };
}

class FragProxy extends EventEmitter {
  constructor({ resolve, strategy }) {
    super();
    this.resolve = resolve;
    this.strategy = strategy;
    this.server = null;
    this.sockets = new Set();
    this.stats = { connections: 0, fragmented: 0, errors: 0 };
  }

  get port() { return this.server?.address()?.port ?? null; }

  start(port = 0) {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((c) => this.handle(c));
      this.server.once('error', reject);
      this.server.listen(port, '127.0.0.1', () => resolve(this.port));
    });
  }

  stop() {
    for (const s of this.sockets) s.destroy();
    this.sockets.clear();
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
      this.server = null;
    });
  }

  track(s) {
    this.sockets.add(s);
    s.once('close', () => this.sockets.delete(s));
    s.on('error', () => {});
  }

  fail(client, err, status = '502 Bad Gateway') {
    this.stats.errors++;
    this.emit('log', `error: ${err.message}`);
    if (client.writable) client.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
  }

  handle(client) {
    this.track(client);
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      let req;
      try { req = parseHead(buf); } catch (e) { client.off('data', onData); return this.fail(client, e, '400 Bad Request'); }
      if (!req) {
        if (buf.length > MAX_HEAD) { client.off('data', onData); this.fail(client, new Error('Request head too large'), '431 Request Header Fields Too Large'); }
        return;
      }
      client.off('data', onData);
      client.pause();
      this.stats.connections++;
      const route = req.method === 'CONNECT' ? this.tunnel(client, req) : this.forward(client, req);
      route.catch((e) => this.fail(client, e));
    };
    client.on('data', onData);
  }

  async connectUpstream(host, port) {
    const ip = await this.resolve(host);
    return new Promise((resolve, reject) => {
      const up = net.connect({ host: ip, port });
      up.setNoDelay(true);
      up.once('connect', () => { up.off('error', reject); this.track(up); resolve(up); });
      up.once('error', reject);
    });
  }

  // CONNECT host:443 — answer 200, then fragment the first ClientHello and pipe.
  async tunnel(client, req) {
    const { host, port } = splitHostPort(req.target, 443);
    const up = await this.connectUpstream(host, port);
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    const hello = await this.readClientHello(client, req.rest);
    if (hello.length) {
      const chunks = fragment(hello, this.strategy);
      if (chunks.length > 1) this.stats.fragmented++;
      await writeChunks(up, chunks);
    }
    this.pipe(client, up);
  }

  // Collect the whole first TLS record (a ClientHello can span several reads).
  readClientHello(client, initial) {
    return new Promise((resolve) => {
      let buf = initial;
      const complete = () => buf.length > 0 && (!isClientHello(buf) || buf.length >= recordLength(buf));
      if (complete()) return resolve(buf);
      const finish = () => { clearTimeout(timer); client.off('data', onData); client.pause(); resolve(buf); };
      const onData = (c) => { buf = Buffer.concat([buf, c]); if (complete()) finish(); };
      const timer = setTimeout(finish, HELLO_WAIT_MS);
      client.on('data', onData);
      client.resume();
    });
  }

  // Plain-HTTP request in absolute form: rewrite to origin form and pass through.
  async forward(client, req) {
    const url = new URL(req.target);
    if (url.protocol !== 'http:') throw new Error(`Unsupported proxy target ${req.target}`);
    const up = await this.connectUpstream(url.hostname, Number(url.port || 80));
    const headers = req.headerLines.filter((h) => !/^(proxy-connection|connection):/i.test(h));
    up.write(`${req.method} ${url.pathname}${url.search} ${req.version}\r\n${headers.join('\r\n')}\r\nConnection: close\r\n\r\n`);
    if (req.rest.length) up.write(req.rest);
    this.pipe(client, up);
  }

  pipe(client, up) {
    client.pipe(up);
    up.pipe(client);
    client.resume();
    client.once('close', () => up.destroy());
    up.once('close', () => client.destroy());
  }
}

module.exports = { FragProxy, parseHead, splitHostPort };
