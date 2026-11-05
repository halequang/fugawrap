'use strict';
// Connection check: for each target host, work out what kind of blocking (if any)
// is in the way, and which mode would get around it.
//
//   ok   handshake succeeds with the system resolver's answer
//   dns  system DNS gives a bad answer, but the real address (via DoH) works
//   sni  TCP connects, the normal handshake fails, a fragmented ClientHello works
//   ip   the address is unreachable, or even a fragmented handshake fails

const net = require('net');
const tls = require('tls');
const dns = require('dns');
const doh = require('./doh');
const { fragmentingDuplex, STRATEGIES } = require('./tls');

const TIMEOUT_MS = 6000;

function isBogus(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168);
}

function tcpProbe(ip, port = 443, timeoutMs = TIMEOUT_MS) {
  return new Promise((resolve) => {
    const started = Date.now();
    const s = net.connect({ host: ip, port });
    const done = (r) => { clearTimeout(timer); s.destroy(); resolve({ ...r, ms: Date.now() - started }); };
    const timer = setTimeout(() => done({ ok: false, error: 'timeout' }), timeoutMs);
    s.once('connect', () => done({ ok: true }));
    s.once('error', (e) => done({ ok: false, error: e.code || e.message }));
  });
}

// Full TLS handshake with certificate validation, optionally with a fragmented ClientHello.
// A DPI block page or injected reset both surface as failures here.
function tlsProbe(ip, host, { strategy = null, timeoutMs = TIMEOUT_MS } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const raw = net.connect({ host: ip, port: 443 });
    raw.setNoDelay(true);
    const socket = tls.connect({
      socket: strategy ? fragmentingDuplex(raw, strategy) : raw,
      servername: host,
      ALPNProtocols: ['http/1.1'],
    });
    let settled = false;
    const done = (r) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      raw.destroy();
      resolve({ ...r, ms: Date.now() - started });
    };
    const timer = setTimeout(() => done({ ok: false, error: 'timeout' }), timeoutMs);
    socket.once('secureConnect', () => done({ ok: true }));
    socket.once('error', (e) => done({ ok: false, error: e.code || e.message }));
    raw.once('error', (e) => done({ ok: false, error: e.code || e.message }));
  });
}

async function systemLookup(host) {
  try {
    return (await dns.promises.lookup(host, { all: true, family: 4 })).map((r) => r.address);
  } catch { return []; }
}

async function checkTarget(host) {
  const [sysIps, dohIps] = await Promise.all([
    systemLookup(host),
    doh.resolve4(host).catch(() => []),
  ]);
  const steps = [];
  const sysIp = sysIps.find((ip) => !isBogus(ip));
  const realIp = dohIps[0] || sysIp;
  const result = (kind, note) => ({ host, kind, note, sysIps, dohIps, steps });

  if (sysIp) {
    const r = await tlsProbe(sysIp, host);
    steps.push({ step: `TLS ${sysIp} (system DNS)`, ...r });
    if (r.ok) return result('ok', 'Reachable normally');
  } else {
    steps.push({ step: 'system DNS', ok: false, error: sysIps.length ? `bogus answer ${sysIps.join(', ')}` : 'no answer' });
  }
  if (!realIp) return result('dns', 'No usable DNS answer from the system or DoH');

  if (realIp !== sysIp) {
    const r = await tlsProbe(realIp, host);
    steps.push({ step: `TLS ${realIp} (DoH)`, ...r });
    if (r.ok) return result('dns', 'System DNS returns a wrong address');
  }

  const tcp = await tcpProbe(realIp);
  steps.push({ step: `TCP ${realIp}:443`, ...tcp });
  if (!tcp.ok) return result('ip', 'Address is unreachable');

  for (const strategy of STRATEGIES) {
    const r = await tlsProbe(realIp, host, { strategy });
    steps.push({ step: `TLS ${realIp} fragmented`, strategy, ...r });
    if (r.ok) return { ...result('sni', 'Blocked by host name; splitting the ClientHello works'), strategy };
  }
  return result('ip', 'Handshake fails even when fragmented');
}

const RECOMMEND = { dns: 'dns', sni: 'optimize', mixed: 'optimize', ip: 'tunnel' };

function summarize(targets) {
  const kinds = targets.map((t) => t.kind);
  const blocked = kinds.filter((k) => k !== 'ok');
  let kind = null;
  if (blocked.length === 0) kind = null;
  else if (blocked.includes('ip')) kind = 'ip';
  else if (blocked.includes('sni')) kind = kinds.includes('ok') ? 'mixed' : 'sni';
  else kind = 'dns';
  return { kind, recommend: kind ? RECOMMEND[kind] : null };
}

async function diagnose(hosts, onProgress = () => {}) {
  const targets = await Promise.all(hosts.map(async (host) => {
    const r = await checkTarget(host);
    onProgress(r);
    return r;
  }));
  return { at: new Date().toISOString(), targets, ...summarize(targets) };
}

// Find the first fragmentation strategy that completes a handshake with `host`.
async function measureStrategy(host) {
  const ip = (await doh.resolve4(host).catch(() => []))[0] ||
    (await systemLookup(host)).find((a) => !isBogus(a));
  if (!ip) return { strategy: null, tried: [], error: `Could not resolve ${host}` };
  const tried = [];
  for (const strategy of STRATEGIES) {
    const r = await tlsProbe(ip, host, { strategy });
    tried.push({ strategy, ...r });
    if (r.ok) return { strategy, tried };
  }
  return { strategy: null, tried };
}

module.exports = { diagnose, measureStrategy, checkTarget, summarize, tlsProbe, tcpProbe, isBogus };
