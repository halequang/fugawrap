'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');

// Load src/renderer/i18n.js in a sandbox with just enough browser globals.
function load(savedLang = null) {
  const store = new Map(savedLang ? [['fugawrap.lang', savedLang]] : []);
  const window = {};
  const ctx = {
    window,
    localStorage: { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v) },
    document: { documentElement: {}, querySelectorAll: () => [] },
  };
  vm.runInNewContext(fs.readFileSync(path.join(ROOT, 'src/renderer/i18n.js'), 'utf8'), ctx);
  return window.i18n;
}

// Every key the UI asks for: data-i18n attributes plus t('...') calls in the renderer.
function usedKeys() {
  const html = fs.readFileSync(path.join(ROOT, 'src/renderer/index.html'), 'utf8');
  const js = fs.readFileSync(path.join(ROOT, 'src/renderer/renderer.js'), 'utf8');
  const keys = new Set([...html.matchAll(/data-i18n(?:-aria)?="([^"]+)"/g)].map((m) => m[1]));
  for (const m of js.matchAll(/\bt\('([^'`]+)'/g)) keys.add(m[1]);
  for (const k of ['ok', 'dns', 'sni', 'ip', 'run']) keys.add(`kind.${k}`);
  for (const k of ['null', 'dns', 'sni', 'mixed', 'ip']) { keys.add(`sum.${k}`); keys.add(`net.${k}`); }
  return keys;
}

test('Vietnamese is the default language', () => {
  const i18n = load();
  assert.equal(i18n.lang, 'vi');
  assert.equal(i18n.t('checkBtn'), 'Kiểm tra');
});

test('a saved choice of English is remembered', () => {
  assert.equal(load('en').t('checkBtn'), 'Check');
});

test('both languages define every key the UI uses, with the same placeholders', () => {
  for (const lang of ['vi', 'en']) {
    const i18n = load(lang);
    for (const key of usedKeys()) {
      assert.notEqual(i18n.t(key), key, `${lang} is missing "${key}"`);
    }
  }
  const vi = load('vi');
  const en = load('en');
  const holes = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
  for (const key of usedKeys()) {
    // Fill nothing: compare raw templates by asking for the placeholder names back.
    const raw = (i18n) => i18n.t(key, new Proxy({}, { get: (_, k) => `{${String(k)}}` }));
    assert.equal(holes(raw(vi)), holes(raw(en)), `placeholders differ for "${key}"`);
  }
});

test('backend messages are translated, unknown ones pass through', () => {
  const vi = load('vi');
  assert.equal(vi.translateBackend('Blocked by host name; splitting the ClientHello works'),
    'Bị chặn theo tên miền; tách ClientHello thì vào được');
  assert.equal(vi.translateBackend('Port 18787 is already in use'), 'Cổng 18787 đang bị app khác dùng.');
  assert.equal(vi.translateBackend('Optimize on: 127.0.0.1:18787, record split mid host name'),
    'Đã bật Tối ưu: 127.0.0.1:18787');
  assert.equal(vi.translateBackend('error: a.b:443: refused'), 'Lỗi: a.b:443: refused');
  assert.equal(vi.translateBackend('Something new'), 'Something new');
});

test('every note the backends send has a translation', () => {
  const vi = load('vi');
  const sources = ['src-tauri/src/probe.rs', 'src/lib/diagnose.js'].map((f) => fs.readFileSync(path.join(ROOT, f), 'utf8'));
  const notes = new Set();
  for (const src of sources) {
    for (const m of src.matchAll(/(?:done|result)\("(?:ok|dns|sni|ip)", "([^"]+)"\)/g)) notes.add(m[1]);
    for (const m of src.matchAll(/result\('(?:ok|dns|sni|ip)', '([^']+)'\)/g)) notes.add(m[1]);
    for (const m of src.matchAll(/result\('sni', '([^']+)'\)/g)) notes.add(m[1]);
  }
  assert.ok(notes.size >= 6, `found ${notes.size} notes`);
  for (const note of notes) assert.notEqual(vi.translateBackend(note), note, `untranslated note: ${note}`);
});
