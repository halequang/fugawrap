'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { isClientHello, findSni, fragment, STRATEGIES } = require('../src/lib/tls');
const { captureClientHello, records } = require('./helpers');

const HOST = 'store.steampowered.com';

test('recognises a real ClientHello and finds its SNI', async () => {
  const hello = await captureClientHello(HOST);
  assert.ok(isClientHello(hello));
  const sni = findSni(hello);
  assert.equal(sni.host, HOST);
  assert.equal(hello.toString('ascii', sni.offset, sni.offset + sni.length), HOST);
});

test('ignores data that is not a ClientHello', () => {
  const http = Buffer.from('GET / HTTP/1.1\r\n\r\n');
  assert.equal(isClientHello(http), false);
  assert.deepEqual(fragment(http, STRATEGIES[0]), [http]);
});

for (const strategy of STRATEGIES) {
  test(`strategy ${JSON.stringify(strategy)} keeps the handshake intact`, async () => {
    const hello = await captureClientHello(HOST);
    const parts = fragment(hello, strategy);
    assert.equal(parts.length, 2, 'splits into two TCP writes');
    const joined = Buffer.concat(parts);

    if (strategy.record === false) {
      assert.deepEqual(joined, hello, 'TCP-only split must not change bytes');
    } else {
      const { records: recs, trailing } = records(joined);
      assert.equal(trailing, 0);
      assert.equal(recs.length, 2, 'two handshake records');
      for (const r of recs) assert.equal(r.type, 0x16);
      assert.deepEqual(Buffer.concat(recs.map((r) => r.payload)), hello.subarray(5), 'payload unchanged');
    }

    // Neither write may contain the whole host name.
    for (const p of parts) {
      if (strategy.kind === 'sni') assert.equal(p.includes(HOST), false);
    }
  });
}

test('host name is split across the two writes for the sni strategy', async () => {
  const hello = await captureClientHello(HOST);
  const [a, b] = fragment(hello, { kind: 'sni' });
  assert.ok(a.includes('store.steam') || a.includes('store.stea'));
  assert.ok(b.includes('powered.com'));
});
