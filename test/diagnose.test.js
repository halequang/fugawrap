'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { summarize, isBogus } = require('../src/lib/diagnose');

const t = (...kinds) => kinds.map((kind) => ({ kind }));

test('summarize picks the mode that fixes the worst block', () => {
  assert.deepEqual(summarize(t('ok', 'ok')), { kind: null, recommend: null });
  assert.deepEqual(summarize(t('dns', 'ok')), { kind: 'dns', recommend: 'dns' });
  assert.deepEqual(summarize(t('sni', 'sni')), { kind: 'sni', recommend: 'optimize' });
  assert.deepEqual(summarize(t('sni', 'ok')), { kind: 'mixed', recommend: 'optimize' });
  assert.deepEqual(summarize(t('dns', 'sni')), { kind: 'sni', recommend: 'optimize' });
  assert.deepEqual(summarize(t('ip', 'sni')), { kind: 'ip', recommend: 'tunnel' });
});

test('isBogus flags private, loopback and null answers', () => {
  for (const ip of ['0.0.0.0', '127.0.0.1', '10.1.2.3', '192.168.1.1', '172.20.0.1', '169.254.1.1', '100.64.0.1']) {
    assert.ok(isBogus(ip), ip);
  }
  for (const ip of ['23.45.67.89', '172.32.0.1', '8.8.8.8']) assert.equal(isBogus(ip), false, ip);
});
