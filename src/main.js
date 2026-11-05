'use strict';
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const fs = require('fs');
const path = require('path');

const { diagnose, measureStrategy } = require('./lib/diagnose');
const { FragProxy } = require('./lib/fragproxy');
const { createResolver } = require('./lib/doh');
const { createSysProxy } = require('./lib/sysproxy');
const { describeStrategy, STRATEGIES } = require('./lib/tls');
const dnsMode = require('./lib/dnsmode');

if (!app.requestSingleInstanceLock()) app.quit();

const DEFAULTS = {
  targets: ['store.steampowered.com', 'api.steampowered.com', 'steamcommunity.com'],
  provider: 'google',
  strategy: STRATEGIES[0],
  proxyPort: 18787,
};

const userFile = (name) => path.join(app.getPath('userData'), name);
let settings = { ...DEFAULTS };
let sysProxy;
let proxy = null;
let win = null;

function loadSettings() {
  try { settings = { ...DEFAULTS, ...JSON.parse(fs.readFileSync(userFile('settings.json'), 'utf8')) }; } catch {}
}
function saveSettings(patch) {
  settings = { ...settings, ...patch };
  fs.writeFileSync(userFile('settings.json'), JSON.stringify(settings, null, 2));
  return settings;
}

const send = (channel, payload) => win?.webContents.send(channel, payload);
const log = (line) => send('log', line);

function optimizeStatus() {
  return {
    running: !!proxy,
    port: proxy?.port ?? null,
    strategy: settings.strategy,
    strategyText: describeStrategy(settings.strategy),
    stats: proxy?.stats ?? null,
  };
}

async function startOptimize() {
  if (proxy) return optimizeStatus();
  const p = new FragProxy({ resolve: createResolver(), strategy: settings.strategy });
  p.on('log', log);
  try {
    await p.start(settings.proxyPort);
  } catch (e) {
    throw new Error(e.code === 'EADDRINUSE' ? `Port ${settings.proxyPort} is already in use` : e.message);
  }
  proxy = p;
  try {
    await sysProxy.enable(proxy.port);
  } catch (e) {
    await stopOptimize();
    throw e;
  }
  log(`Optimize on: 127.0.0.1:${proxy.port}, ${describeStrategy(settings.strategy)}`);
  return optimizeStatus();
}

async function stopOptimize() {
  await sysProxy.restore();
  if (proxy) { await proxy.stop(); proxy = null; log('Optimize off, system proxy restored'); }
  return optimizeStatus();
}

// Wrap handlers so errors reach the UI as { error } instead of rejected promises.
function handle(channel, fn) {
  ipcMain.handle(channel, async (_e, ...args) => {
    try { return { ok: true, value: await fn(...args) }; } catch (e) { return { ok: false, error: e.message }; }
  });
}

handle('settings:get', () => ({ settings, providers: dnsMode.PROVIDERS }));
handle('settings:targets', (targets) => {
  // Dotted DNS names only: single words ("bad", "host") can't be public sites.
  const label = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const isHost = (t) => t.length <= 253 && t.split('.').length >= 2 && t.split('.').every((l) => label.test(l));
  const clean = [...new Set(targets.map((t) => String(t).trim().toLowerCase()).filter(isHost))];
  if (!clean.length) throw new Error('Add at least one host name');
  return saveSettings({ targets: clean });
});
handle('diagnose', () => diagnose(settings.targets, (r) => send('diagnose:progress', r)));

handle('dns:status', () => dnsMode.status());
handle('dns:set', async (provider) => {
  const r = await dnsMode.set(provider);
  saveSettings({ provider });
  return r;
});
handle('dns:restore', () => dnsMode.restore());

handle('optimize:status', () => optimizeStatus());
handle('optimize:start', () => startOptimize());
handle('optimize:stop', () => stopOptimize());
handle('optimize:measure', async (host) => {
  const r = await measureStrategy(host || settings.targets[0]);
  if (r.strategy) {
    saveSettings({ strategy: r.strategy });
    if (proxy) proxy.strategy = r.strategy;
  }
  return { ...r, strategyText: describeStrategy(r.strategy), status: optimizeStatus() };
});

function createWindow() {
  win = new BrowserWindow({
    width: 420,
    height: 680,
    resizable: false,
    autoHideMenuBar: true,
    title: 'FugaWrap',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    backgroundColor: '#0f1115',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.on('closed', () => { win = null; });
}

app.on('second-instance', () => { if (win) { win.restore(); win.focus(); } });

app.whenReady().then(async () => {
  loadSettings();
  sysProxy = createSysProxy(userFile('sysproxy-backup.json'));
  // A backup left behind means we crashed with the system proxy pointing at a
  // proxy that no longer exists, which breaks the user's browsing. Fix it first.
  if (sysProxy.pending()) {
    await sysProxy.restore().catch(() => {});
    console.log('Restored system proxy left over from an unclean exit');
  }
  createWindow();
});

// Never leave the system proxy pointing at a dead port.
let cleanedUp = false;
app.on('before-quit', (e) => {
  if (cleanedUp) return;
  e.preventDefault();
  stopOptimize().catch(() => {}).finally(() => { cleanedUp = true; app.quit(); });
});

app.on('window-all-closed', () => app.quit());
