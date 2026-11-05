'use strict';
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const { FragProxy, parseHead, splitHostPort } = require('../src/lib/fragproxy');
const { captureClientHello, records } = require('./helpers');

// Fake upstream: records every 'data' event it receives.
function upstream() {
  return new Promise((resolve) => {
    const received = [];
    const server = net.createServer((s) => {
      s.on('data', (d) => received.push(Buffer.from(d)));
      s.on('error', () => {});
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, received, port: server.address().port }));
  });
}

function connectThrough(proxyPort, request) {
  return new Promise((resolve, reject) => {
    const c = net.connect(proxyPort, '127.0.0.1', () => c.write(request));
    let reply = '';
    c.on('data', (d) => {
      reply += d.toString('latin1');
      if (reply.includes('\r\n\r\n')) resolve({ c, reply });
    });
    c.on('error', reject);
  });
}

const until = async (cond, ms = 2000) => {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error('timed out waiting');
    await new Promise((r) => setTimeout(r, 10));
  }
};

test('parseHead waits for a full head and keeps trailing bytes', () => {
  assert.equal(parseHead(Buffer.from('CONNECT a:443 HTTP/1.1\r\nHost: a')), null);
  const r = parseHead(Buffer.from('CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\nXYZ'));
  assert.equal(r.method, 'CONNECT');
  assert.equal(r.target, 'a:443');
  assert.equal(r.rest.toString(), 'XYZ');
});

test('splitHostPort handles names, ports and IPv6 literals', () => {
  assert.deepEqual(splitHostPort('example.com:8443', 443), { host: 'example.com', port: 8443 });
  assert.deepEqual(splitHostPort('example.com', 443), { host: 'example.com', port: 443 });
  assert.deepEqual(splitHostPort('[::1]:443', 443), { host: '::1', port: 443 });
});

test('CONNECT tunnel splits the ClientHello and passes the rest through', async (t) => {
  const up = await upstream();
  const proxy = new FragProxy({ resolve: async () => '127.0.0.1', strategy: { kind: 'sni' } });
  const port = await proxy.start(0);
  t.after(async () => { await proxy.stop(); up.server.close(); });

  const { c, reply } = await connectThrough(port, `CONNECT store.steampowered.com:${up.port} HTTP/1.1\r\n\r\n`);
  assert.match(reply, /^HTTP\/1\.1 200/);

  const hello = await captureClientHello('store.steampowered.com');
  c.write(hello);
  await until(() => Buffer.concat(up.received).length >= hello.length + 5);

  const got = Buffer.concat(up.received);
  const { records: recs } = records(got);
  assert.equal(recs.length, 2, 'ClientHello arrives as two records');
  assert.deepEqual(Buffer.concat(recs.map((r) => r.payload)), hello.subarray(5));
  assert.ok(up.received.length >= 2, 'and in at least two TCP reads');
  assert.equal(proxy.stats.fragmented, 1);

  c.write('after');
  await until(() => Buffer.concat(up.received).toString('latin1').endsWith('after'));
  c.destroy();
});

test('plain HTTP requests are rewritten to origin form', async (t) => {
  const up = await upstream();
  const proxy = new FragProxy({ resolve: async () => '127.0.0.1', strategy: { kind: 'sni' } });
  const port = await proxy.start(0);
  t.after(async () => { await proxy.stop(); up.server.close(); });

  const c = net.connect(port, '127.0.0.1');
  c.write(`GET http://example.test:${up.port}/a?b=1 HTTP/1.1\r\nHost: example.test\r\nProxy-Connection: keep-alive\r\n\r\n`);
  await until(() => Buffer.concat(up.received).includes('\r\n\r\n'));
  const head = Buffer.concat(up.received).toString('latin1');
  assert.match(head, /^GET \/a\?b=1 HTTP\/1\.1\r\n/);
  assert.doesNotMatch(head, /Proxy-Connection/i);
  assert.match(head, /Connection: close/);
  c.destroy();
});

test('upstream failure answers 502', async (t) => {
  const proxy = new FragProxy({ resolve: async () => { throw new Error('no such host'); }, strategy: null });
  const port = await proxy.start(0);
  t.after(() => proxy.stop());
  const { reply } = await connectThrough(port, 'CONNECT nowhere.invalid:443 HTTP/1.1\r\n\r\n');
  assert.match(reply, /^HTTP\/1\.1 502/);
  assert.equal(proxy.stats.errors, 1);
});
