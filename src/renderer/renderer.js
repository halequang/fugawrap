'use strict';
const api = window.netfix;
const $ = (id) => document.getElementById(id);

const KIND_LABEL = { ok: 'OK', dns: 'DNS block', sni: 'SNI block', ip: 'IP block', run: 'Checking…' };
const SUMMARY = {
  null: ['All hosts reachable. No fix needed.', 'ok'],
  dns: ['Blocked by DNS. Use DNS mode.', 'warn'],
  sni: ['Blocked by host name (SNI). Use Optimize.', 'warn'],
  mixed: ['Blocked by host name on some hosts. Use Optimize.', 'warn'],
  ip: ['Blocked by address. That needs a VPN or tunnel, which this app does not include.', 'bad'],
};

let settings = null;
let providers = {};
let selectedProvider = 'google';
let dns = null;
let optimize = null;
let busy = false;

function say(text, bad = false) {
  $('log').textContent = text || '';
  $('log').className = 'log' + (bad ? ' bad' : '');
}

// Run an API call with all buttons disabled; report errors in the footer.
async function act(fn) {
  if (busy) return null;
  busy = true;
  document.querySelectorAll('button').forEach((b) => { b.disabled = true; });
  try {
    const r = await fn();
    if (r && r.ok === false) { say(r.error, true); return null; }
    return r?.value ?? r;
  } finally {
    busy = false;
    document.querySelectorAll('button').forEach((b) => { b.disabled = false; });
    renderDns();
    renderOptimize();
  }
}

// ---------------------------------------------------------------- check

function targetRow(host, kind, note) {
  const li = document.createElement('li');
  const name = document.createElement('span');
  name.className = 'host';
  name.textContent = host;
  const badge = document.createElement('span');
  badge.className = `badge ${kind}`;
  badge.textContent = KIND_LABEL[kind] || kind;
  li.append(name, badge);
  if (note) {
    const n = document.createElement('span');
    n.className = 'note';
    n.textContent = note;
    li.append(n);
  }
  li.dataset.host = host;
  return li;
}

function renderTargets(results = {}) {
  $('targets').replaceChildren(...settings.targets.map((h) => {
    const r = results[h];
    return r ? targetRow(h, r.kind, r.note) : targetRow(h, 'idle', '');
  }));
  document.querySelectorAll('.badge.idle').forEach((b) => { b.textContent = '—'; });
}

function recommend(mode) {
  document.querySelectorAll('.tabs button').forEach((b) => {
    b.classList.toggle('recommended', b.dataset.tab === mode);
  });
}

async function runCheck() {
  const results = {};
  settings.targets.forEach((h) => { results[h] = { kind: 'run', note: '' }; });
  renderTargets(results);
  $('summary').textContent = 'Checking…';
  $('summary').className = 'summary muted';
  const off = api.onProgress((r) => { results[r.host] = r; renderTargets(results); });
  const report = await act(() => api.diagnose());
  off();
  if (!report) return;
  const [text, cls] = SUMMARY[report.kind];
  $('summary').textContent = text;
  $('summary').className = `summary ${cls}`;
  recommend(report.recommend);
  if (report.recommend === 'dns' || report.recommend === 'optimize') showTab(report.recommend);
  const sni = report.targets.find((t) => t.strategy);
  if (sni) say(`${sni.host}: works with ${describe(sni.strategy)}`);
}

function describe(s) {
  if (!s) return 'none';
  const where = s.kind === 'sni' ? 'mid host name' : `after ${s.n} byte${s.n === 1 ? '' : 's'}`;
  return s.record === false ? `TCP split ${where}` : `record split ${where}`;
}

// ---------------------------------------------------------------- tabs

function showTab(name) {
  document.querySelectorAll('.tabs button').forEach((b) => {
    b.setAttribute('aria-selected', String(b.dataset.tab === name));
  });
  $('panel-dns').hidden = name !== 'dns';
  $('panel-optimize').hidden = name !== 'optimize';
}

// ---------------------------------------------------------------- dns

function renderProviders() {
  $('providers').replaceChildren(...Object.entries(providers).map(([key, label]) => {
    const b = document.createElement('button');
    b.textContent = label;
    b.setAttribute('role', 'radio');
    b.setAttribute('aria-checked', String(key === selectedProvider));
    b.onclick = () => { selectedProvider = key; renderProviders(); };
    return b;
  }));
}

function renderDns() {
  if (!dns) return;
  const where = dns.adapter ? ` on ${dns.adapter.name}` : '';
  if (dns.active) {
    $('dnsState').innerHTML = '';
    const on = document.createElement('span');
    on.className = 'on';
    on.textContent = `Using ${providers[dns.provider] || dns.provider} with DNS-over-HTTPS${where}.`;
    $('dnsState').append(on);
  } else {
    const servers = dns.adapter?.servers?.length ? dns.adapter.servers.join(', ') : 'automatic';
    $('dnsState').textContent = `Network default${where}: ${servers}`;
  }
  if (!busy) $('dnsUndo').disabled = !dns.active;
}

async function refreshDns() {
  const r = await api.dnsStatus();
  if (r.ok) { dns = r.value; renderDns(); }
}

// ---------------------------------------------------------------- optimize

function renderOptimize() {
  if (!optimize) return;
  $('optState').textContent = optimize.running ? `On · 127.0.0.1:${optimize.port}` : 'Off';
  $('optState').className = optimize.running ? 'on' : '';
  $('optStrategy').textContent = optimize.strategyText;
  const s = optimize.stats;
  $('optStats').textContent = s
    ? `${s.connections} connections, ${s.fragmented} ClientHellos split, ${s.errors} errors`
    : '—';
  $('optToggle').textContent = optimize.running ? 'Stop' : 'Start';
}

async function refreshOptimize() {
  const r = await api.optimizeStatus();
  if (r.ok) { optimize = r.value; renderOptimize(); }
}

// ---------------------------------------------------------------- wiring

$('checkBtn').onclick = runCheck;
document.querySelectorAll('.tabs button').forEach((b) => { b.onclick = () => showTab(b.dataset.tab); });

$('targetsSave').onclick = async () => {
  const list = $('targetsInput').value.split(/\s+/).filter(Boolean);
  const s = await act(() => api.setTargets(list));
  if (s) { settings = s; $('targetsInput').value = s.targets.join('\n'); renderTargets(); say('Hosts saved'); }
};

$('dnsApply').onclick = async () => {
  say(`Switching DNS to ${providers[selectedProvider]}… approve the Windows prompt.`);
  const r = await act(() => api.dnsSet(selectedProvider));
  if (r) { dns = r; say('DNS changed. Run the check again to confirm.'); }
};

$('dnsUndo').onclick = async () => {
  say('Restoring your previous DNS… approve the Windows prompt.');
  const r = await act(() => api.dnsRestore());
  if (r) { dns = r; say('Previous DNS restored.'); }
};

$('optToggle').onclick = async () => {
  const r = await act(() => (optimize?.running ? api.optimizeStop() : api.optimizeStart()));
  if (r) { optimize = r; say(r.running ? 'Optimize is on. Restart apps that were already open.' : 'Optimize is off.'); }
};

$('optMeasure').onclick = async () => {
  say('Trying each way of splitting the handshake…');
  const r = await act(() => api.optimizeMeasure());
  if (!r) return;
  optimize = r.status;
  say(r.strategy ? `Best split: ${r.strategyText}` : (r.error || 'No split got through. The block may be by address.'), !r.strategy);
};

api.onLog((line) => say(line));
// Keep the traffic counters current while the proxy runs.
setInterval(() => { if (optimize?.running && !busy) refreshOptimize(); }, 2000);

(async () => {
  const r = await api.getSettings();
  settings = r.value.settings;
  providers = r.value.providers;
  selectedProvider = settings.provider;
  $('targetsInput').value = settings.targets.join('\n');
  renderTargets();
  renderProviders();
  await Promise.all([refreshDns(), refreshOptimize()]);
})();
