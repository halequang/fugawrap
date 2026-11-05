'use strict';
// DNS-over-HTTPS A-record lookups, addressed by IP so they never depend on the
// (possibly poisoned) system resolver. Both certificates carry an IP SAN.

const https = require('https');
const dns = require('dns');
const net = require('net');

const ENDPOINTS = [
  { ip: '1.1.1.1', path: '/dns-query' },
  { ip: '8.8.8.8', path: '/resolve' },
];

function query(ep, name, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = https.get({
      host: ep.ip,
      path: `${ep.path}?name=${encodeURIComponent(name)}&type=A`,
      headers: { accept: 'application/dns-json' },
      timeout: timeoutMs,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`DoH ${ep.ip}: HTTP ${res.statusCode}`));
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => {
        body += c;
        if (body.length > 65536) req.destroy(new Error(`DoH ${ep.ip}: response too large`));
      });
      res.on('end', () => {
        try {
          const answers = JSON.parse(body).Answer || [];
          resolve(answers.filter((a) => a.type === 1).map((a) => a.data));
        } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => req.destroy(new Error(`DoH ${ep.ip}: timed out`)));
    req.on('error', reject);
  });
}

async function resolve4(name, timeoutMs = 4000) {
  let lastErr = null;
  for (const ep of ENDPOINTS) {
    try {
      const ips = await query(ep, name, timeoutMs);
      if (ips.length) return ips;
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error(`DoH: no A records for ${name}`);
}

// Resolver for the proxy: DoH first, system DNS as a fallback, with a small TTL cache.
function createResolver({ ttlMs = 5 * 60 * 1000 } = {}) {
  const cache = new Map();
  return async function resolveHost(host) {
    if (net.isIP(host)) return host;
    const hit = cache.get(host);
    if (hit && hit.expires > Date.now()) return hit.ip;
    let ip;
    try {
      ip = (await resolve4(host))[0];
    } catch {
      ip = (await dns.promises.lookup(host, { family: 4 })).address;
    }
    cache.set(host, { ip, expires: Date.now() + ttlMs });
    return ip;
  };
}

module.exports = { resolve4, createResolver };
