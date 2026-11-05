# NetFix

A Windows desktop app that works out *why* a site is unreachable and applies the
fix that matches. Modelled on the backend of RevoltWarp 1.2.1, without its drivers
or bundled third-party binaries.

```
npm install
npm start          # run the app
npm test           # unit + local proxy tests (no network)
npm run check      # connection check from the command line (uses the network)
```

## What it does

**Connection check** (`src/lib/diagnose.js`). For each host (default: Steam's store,
API and community sites) it compares system DNS with DNS-over-HTTPS and runs real,
certificate-validated TLS handshakes:

| Result | Meaning | Fix |
|---|---|---|
| OK | Handshake works with the system's DNS answer | none |
| DNS block | System DNS answer is wrong; the DoH answer works | DNS mode |
| SNI block | TCP connects; normal handshake fails; split ClientHello works | Optimize |
| IP block | Address unreachable, or even a split handshake fails | needs a VPN (not included) |

**DNS mode** (`src/lib/dnsmode.js`, `src/scripts/dns.ps1`). Sets the active adapter
(the one owning the best default route) to Google, OpenDNS, AdGuard, Alibaba or
Cloudflare, registers DNS-over-HTTPS on Windows 11, and saves the original servers
so Undo restores them. One UAC prompt per change.

**Optimize** (`src/lib/fragproxy.js`, `src/lib/tls.js`). A local HTTP proxy on
`127.0.0.1:18787`, set as the Windows system proxy while it runs. Each TLS
ClientHello it forwards is split into two records sent as separate TCP segments,
so the host name never appears whole in one packet. Destination names are resolved
over DoH, so DNS poisoning doesn't affect it either. "Find best split" tries the
methods in `STRATEGIES` and keeps the first one that completes a handshake.

## Compared with RevoltWarp

Taken from RevoltWarp (observed in its binary):
- the check → recommended-mode flow and the dns / sni / ip classification;
- DNS mode: picking the adapter by default-route metric, keeping the *original*
  servers across repeated sets, DoH template registration plus `DohFlags` registry
  keys, and restore;
- splitting the ClientHello and measuring which cut a network lets through.

Different by design:
- **Proxy instead of WinDivert.** No kernel driver and no admin rights for
  Optimize, but it only covers apps that use the Windows proxy setting. RevoltWarp
  catches all traffic from chosen processes.
- **No WARP tunnel.** RevoltWarp bundles usque, Wintun and WinDivert for that.
- **No scripts on disk.** RevoltWarp writes `.ps1` files to
  `C:\ProgramData\RevoltWarp`, which every local user can write to, and runs them
  as admin. NetFix passes scripts in memory (`src/lib/ps.js`), and the DNS state
  folder `C:\ProgramData\NetFix` is restricted to administrators and SYSTEM.
- **Crash safety for the proxy.** The previous proxy settings are saved before they
  change, then restored on quit and on the next start after a crash.
- Refuses to overwrite saved DNS state that belongs to another adapter.

## Limits

- Windows only. DNS-over-HTTPS registration needs Windows 11; on Windows 10 only
  the plain DNS servers change.
- Apps that ignore the system proxy (raw sockets, games, some launchers) are not
  covered by Optimize.
- Apps that are already running may need a restart to pick up the proxy.
- An "IP block" result means only a VPN or tunnel will help.
- Don't run DNS mode while another tool (such as RevoltWarp) manages DNS: NetFix
  would save that tool's servers as your "original" ones.
