'use strict';
const api = window.fugawrap;
const { t, translateBackend } = window.i18n;
const $ = (id) => document.getElementById(id);

const SUMMARY_CLASS = { null: 'ok', dns: 'warn', sni: 'warn', mixed: 'warn', ip: 'bad' };

let settings = null;
let providers = {};
let selectedProvider = 'google';
let dns = null;
let optimize = null;
let busy = false;
// Kept so a language switch can redraw them.
let results = {};
let report = null;
let lastSay = null;

// Footer message. `text` is a function so it re-renders in the current language.
function say(text, bad = false) {
  lastSay = text ? { text, bad } : null;
  $('log').textContent = text ? text() : '';
  $('log').className = 'log' + (bad ? ' bad' : '');
}

// Run an API call with all buttons disabled; report errors in the footer.
async function act(fn) {
  if (busy) return null;
  busy = true;
  document.querySelectorAll('button').forEach((b) => { b.disabled = true; });
  try {
    const r = await fn();
    if (r && r.ok === false) { say(() => translateBackend(r.error), true); return null; }
    return r?.value ?? r;
  } finally {
    busy = false;
    document.querySelectorAll('button').forEach((b) => { b.disabled = false; });
    renderDns();
    renderOptimize();
  }
}

// ---------------------------------------------------------------- check

function badge(cls, text) {
  const b = document.createElement('span');
  b.className = `badge ${cls}`;
  b.textContent = text;
  return b;
}

function targetRow(host, r) {
  const li = document.createElement('li');
  const name = document.createElement('span');
  name.className = 'host';
  name.textContent = host;
  const badges = document.createElement('span');
  badges.className = 'badges';
  badges.append(r ? badge(r.kind, t(`kind.${r.kind}`)) : badge('idle', '—'));
  if (r?.viaOptimize === true) badges.append(badge('ok', t('badge.optOk')));
  if (r?.viaOptimize === false) badges.append(badge('ip', t('badge.optBad')));
  li.append(name, badges);
  if (r?.note) {
    const n = document.createElement('span');
    n.className = 'note';
    n.textContent = translateBackend(r.note);
    li.append(n);
  }
  li.dataset.host = host;
  return li;
}

function renderTargets() {
  $('targets').replaceChildren(...settings.targets.map((h) => targetRow(h, results[h])));
}

function optimizeSummary(o) {
  if (o.working === o.total) return [t('opt.all', o), 'ok'];
  if (o.working === 0) return [t('opt.none'), 'bad'];
  return [t('opt.some', o), 'warn'];
}

function renderSummary() {
  if (!report) return;
  let text = t(`sum.${report.kind}`);
  let cls = SUMMARY_CLASS[report.kind];
  // While Optimize runs the check also tests through it; then the summary reports
  // the network's block type plus whether Optimize gets through.
  if (report.optimize) {
    const [optText, optCls] = optimizeSummary(report.optimize);
    text = `${t(`net.${report.kind}`)} ${optText}`;
    cls = optCls;
  }
  $('summary').textContent = text;
  $('summary').className = `summary ${cls}`;
}

function recommend(mode) {
  document.querySelectorAll('.tabs button').forEach((b) => {
    b.classList.toggle('recommended', b.dataset.tab === mode);
  });
}

async function runCheck() {
  results = {};
  report = null;
  settings.targets.forEach((h) => { results[h] = { kind: 'run' }; });
  renderTargets();
  $('summary').textContent = t('checking');
  $('summary').className = 'summary muted';
  const off = api.onProgress((r) => { results[r.host] = r; renderTargets(); });
  const r = await act(() => api.diagnose());
  off();
  if (!r) return;
  report = r;
  renderSummary();
  recommend(report.recommend);
  if (report.recommend === 'dns' || report.recommend === 'optimize') showTab(report.recommend);
  if (optimize?.running) refreshOptimize(); // counters paused while the check ran
  const sni = report.targets.find((x) => x.strategy);
  if (sni) say(() => t('worksWith', { host: sni.host, how: describe(sni.strategy) }));
}

function describe(s) {
  if (!s) return t('split.none');
  const where = s.kind === 'sni' ? t('split.mid') : (s.n === 1 ? t('split.after1') : t('split.afterN', { n: s.n }));
  return t(s.record === false ? 'split.tcp' : 'split.record', { where });
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
  const adapter = dns.adapter?.name;
  if (dns.active) {
    const on = document.createElement('span');
    on.className = 'on';
    on.textContent = t(adapter ? 'dns.usingOn' : 'dns.using', { provider: providers[dns.provider] || dns.provider, adapter });
    $('dnsState').replaceChildren(on);
  } else {
    const servers = dns.adapter?.servers?.length ? dns.adapter.servers.join(', ') : t('dns.automatic');
    $('dnsState').textContent = t(adapter ? 'dns.defaultOn' : 'dns.default', { adapter, servers });
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
  $('optState').textContent = optimize.running ? t('opt.on', { port: optimize.port }) : t('off');
  $('optState').className = optimize.running ? 'on' : '';
  $('optStrategy').textContent = describe(optimize.strategy);
  const s = optimize.stats;
  $('optStats').textContent = s ? t('stats', { c: s.connections, f: s.fragmented, e: s.errors }) : '—';
  $('optToggle').textContent = optimize.running ? t('stop') : t('start');
}

async function refreshOptimize() {
  const r = await api.optimizeStatus();
  if (r.ok) { optimize = r.value; renderOptimize(); }
}

// ---------------------------------------------------------------- language

function renderAll() {
  window.i18n.apply();
  document.querySelectorAll('.tabs button').forEach((b) => { b.dataset.badge = t('recommended'); });
  if (settings) renderTargets();
  if (report) renderSummary();
  renderDns();
  renderOptimize();
  if (lastSay) say(lastSay.text, lastSay.bad);
}

$('langBtn').onclick = () => {
  window.i18n.setLang(window.i18n.lang === 'vi' ? 'en' : 'vi');
  renderAll();
};

// ---------------------------------------------------------------- wiring

$('checkBtn').onclick = runCheck;
document.querySelectorAll('.tabs button').forEach((b) => { b.onclick = () => showTab(b.dataset.tab); });

$('targetsSave').onclick = async () => {
  const list = $('targetsInput').value.split(/\s+/).filter(Boolean);
  const s = await act(() => api.setTargets(list));
  if (s) { settings = s; results = {}; $('targetsInput').value = s.targets.join('\n'); renderTargets(); say(() => t('hostsSaved')); }
};

$('dnsApply').onclick = async () => {
  const provider = providers[selectedProvider];
  say(() => t('dns.switching', { provider }));
  const r = await act(() => api.dnsSet(selectedProvider));
  if (r) { dns = r; renderDns(); say(() => t('dns.changed')); }
};

$('dnsUndo').onclick = async () => {
  say(() => t('dns.restoring'));
  const r = await act(() => api.dnsRestore());
  if (r) { dns = r; renderDns(); say(() => t('dns.restored')); }
};

$('optToggle').onclick = async () => {
  const r = await act(() => (optimize?.running ? api.optimizeStop() : api.optimizeStart()));
  if (r) { optimize = r; renderOptimize(); say(() => t(r.running ? 'opt.started' : 'opt.stopped')); }
};

$('optMeasure').onclick = async () => {
  say(() => t('measure.trying'));
  const r = await act(() => api.optimizeMeasure());
  if (!r) return;
  optimize = r.status;
  renderOptimize();
  if (r.strategy) say(() => t('measure.best', { how: describe(r.strategy) }));
  else say(() => (r.error ? translateBackend(r.error) : t('measure.none')), true);
};

api.onLog((line) => say(() => translateBackend(line)));
// Keep the traffic counters current while the proxy runs.
setInterval(() => { if (optimize?.running && !busy) refreshOptimize(); }, 2000);

renderAll();
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
