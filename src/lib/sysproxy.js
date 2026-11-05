'use strict';
// Point the Windows (WinINET) system proxy at the local fragmenting proxy, and put
// the user's previous settings back. Per-user settings, so no admin rights needed.
// The previous settings are saved to disk first, so a crash can be undone on the
// next start.

const fs = require('fs');
const { runPs, psQuote } = require('./ps');

const KEY = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

// Tell running apps the settings changed (INTERNET_OPTION_SETTINGS_CHANGED, _REFRESH).
const NOTIFY = `
Add-Type -Namespace NetFix -Name WinInet -MemberDefinition '[DllImport("wininet.dll")] public static extern bool InternetSetOption(System.IntPtr h, int o, System.IntPtr b, int l);'
[NetFix.WinInet]::InternetSetOption([System.IntPtr]::Zero, 39, [System.IntPtr]::Zero, 0) | Out-Null
[NetFix.WinInet]::InternetSetOption([System.IntPtr]::Zero, 37, [System.IntPtr]::Zero, 0) | Out-Null`;

async function read() {
  const r = await runPs(`
$p = Get-ItemProperty -Path '${KEY}'
@{ ProxyEnable = [int]$p.ProxyEnable; ProxyServer = $p.ProxyServer; ProxyOverride = $p.ProxyOverride; AutoConfigURL = $p.AutoConfigURL } | ConvertTo-Json -Compress`);
  return JSON.parse(r.stdout);
}

function valueLine(name, value) {
  return value == null || value === ''
    ? `Remove-ItemProperty -Path '${KEY}' -Name '${name}' -ErrorAction SilentlyContinue`
    : `Set-ItemProperty -Path '${KEY}' -Name '${name}' -Value ${psQuote(value)}`;
}

async function write(s) {
  const r = await runPs([
    `Set-ItemProperty -Path '${KEY}' -Name 'ProxyEnable' -Value ${Number(s.ProxyEnable) ? 1 : 0} -Type DWord`,
    valueLine('ProxyServer', s.ProxyServer),
    valueLine('ProxyOverride', s.ProxyOverride),
    valueLine('AutoConfigURL', s.AutoConfigURL),
    NOTIFY,
  ].join('\n'));
  if (r.code !== 0) throw new Error(`Could not change the system proxy: ${r.stderr}`);
}

function createSysProxy(backupFile) {
  const loadBackup = () => {
    try { return JSON.parse(fs.readFileSync(backupFile, 'utf8')); } catch { return null; }
  };

  return {
    async enable(port) {
      // Keep the oldest backup: if we are already enabled, the current values are ours.
      if (!loadBackup()) fs.writeFileSync(backupFile, JSON.stringify(await read()));
      await write({
        ProxyEnable: 1,
        ProxyServer: `127.0.0.1:${port}`,
        ProxyOverride: '<local>;localhost;127.*;10.*;192.168.*',
        AutoConfigURL: null, // a PAC script would take precedence over our proxy
      });
    },
    async restore() {
      const backup = loadBackup();
      if (!backup) return false;
      await write(backup);
      fs.rmSync(backupFile, { force: true });
      return true;
    },
    pending: () => !!loadBackup(),
  };
}

module.exports = { createSysProxy };
