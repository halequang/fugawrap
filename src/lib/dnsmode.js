'use strict';
// DNS mode: switch the active adapter to a public resolver with DNS-over-HTTPS,
// and undo it. Changing DNS needs administrator rights (one UAC prompt per action);
// reading the current state does not.

const fs = require('fs');
const path = require('path');
const { runPs, runPsElevated, psQuote } = require('./ps');

const PROVIDERS = {
  google: 'Google',
  opendns: 'OpenDNS',
  adguard: 'AdGuard',
  alibaba: 'Alibaba',
  cloudflare: 'Cloudflare',
};

const STATE_DIR = path.join(process.env.ProgramData || 'C:\\ProgramData', 'NetFix');
const STATE_FILE = path.join(STATE_DIR, 'dns-state.json');
const LOG_FILE = path.join(STATE_DIR, 'dns.log');
const SCRIPT = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'dns.ps1'), 'utf8');

const EXIT = {
  2: 'No active network adapter found',
  3: 'Nothing to restore',
  4: 'DNS was changed on a different network adapter. Undo it first, then apply again.',
};

function readState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8').replace(/^\uFEFF/, ''));
  } catch { return null; }
}

function lastLogLine() {
  try {
    const lines = fs.readFileSync(LOG_FILE, 'utf8').trim().split(/\r?\n/);
    return lines[lines.length - 1] || '';
  } catch { return ''; }
}

async function currentServers() {
  const r = await runPs(`
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
if ($route) {
  $a = Get-NetAdapter -InterfaceIndex $route.ifIndex
  @{ name = $a.Name; servers = @((Get-DnsClientServerAddress -InterfaceIndex $route.ifIndex).ServerAddresses) } | ConvertTo-Json -Compress
}`);
  try { return JSON.parse(r.stdout); } catch { return null; }
}

async function status() {
  const [state, adapter] = [readState(), await currentServers()];
  return { active: !!state, provider: state?.provider ?? null, original: state?.dns ?? null, adapter };
}

async function run(mode, provider) {
  const prefix = `$Mode = ${psQuote(mode)}; $Provider = ${psQuote(provider || '')}\n`;
  const r = await runPsElevated(prefix + SCRIPT);
  if (r.code !== 0) throw new Error(EXIT[r.code] || `DNS script failed (exit ${r.code}): ${lastLogLine()}`);
  return { ...(await status()), log: lastLogLine() };
}

function set(provider) {
  if (!Object.hasOwn(PROVIDERS, provider)) throw new Error(`Unknown DNS provider: ${provider}`);
  return run('set', provider);
}

const restore = () => run('restore');

module.exports = { PROVIDERS, status, set, restore };
