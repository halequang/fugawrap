# FugaWrap

A Windows and macOS desktop app from FunGaming ([fungamingvn](https://www.facebook.com/fungamingvn)) that works out *why* a site is unreachable and applies the
fix that matches. Modelled on the backend of RevoltWarp 1.2.1, without its drivers
or bundled third-party binaries.

The app has two builds that share one UI (`src/renderer/`):

| Build | Backend | App size | Installer |
|---|---|---|---|
| **Tauri** (main, Windows + macOS) | Rust, `src-tauri/` | 4.1 MB | 1.6 MB |
| Electron (Windows only) | Node.js, `src/main.js` + `src/lib/` | 98 MB portable | 108 MB |

The Tauri build uses the system web view (WebView2 on Windows, WKWebView on macOS);
Electron ships its own Chromium.

## Quick start

```
npm install
npm run tauri:dev      # run the Tauri app, rebuilding on changes
npm run tauri:build    # release exe + installer
npm run tauri:test     # Rust unit tests

npm start              # run the Electron app
npm test               # Node unit + local proxy tests (no network)
npm run check          # connection check from the command line (uses the network)
npm run dist           # Electron portable exe + installer
```

Building the Tauri app needs Rust (`winget install Rustlang.Rustup`) and Visual
Studio Build Tools 2022 with the C++ workload. Open a new terminal after
installing so `cargo` is on PATH.

On macOS, building needs the Xcode command line tools (`xcode-select --install`)
and Rust (`curl https://sh.rustup.rs -sSf | sh`). `npm run tauri:build` then makes
an `.app` and a `.dmg`.

Build output:

| File | Path |
|---|---|
| Tauri app | `src-tauri/target/release/fugawrap.exe` |
| Tauri installer | `src-tauri/target/release/bundle/nsis/FugaWrap_<version>_x64-setup.exe` |
| Tauri macOS app | `src-tauri/target/release/bundle/macos/FugaWrap.app`, `bundle/dmg/FugaWrap_<version>_aarch64.dmg` |
| Electron | `dist/FugaWrap-<version>-portable.exe`, `dist/FugaWrap-<version>-setup.exe` |

The installers are not code-signed, so Windows shows "Windows protected your PC";
choose **More info → Run anyway**. The macOS app is not signed or notarized either:
the first time, right-click it and choose **Open** (or allow it under System
Settings → Privacy & Security).

## What it does

**Connection check** (`src-tauri/src/probe.rs`, `src/lib/diagnose.js`). For each
host (default: Steam's store, API and community sites) it compares system DNS with
DNS-over-HTTPS and runs real, certificate-validated TLS handshakes:

| Result | Meaning | Fix |
|---|---|---|
| OK | Handshake works with the system's DNS answer | none |
| DNS block | System DNS answer is wrong; the DoH answer works | DNS mode |
| SNI block | TCP connects; normal handshake fails; split ClientHello works | Optimize |
| IP block | Address unreachable, or even a split handshake fails | needs a VPN (not included) |

The verdict always describes the raw network, so it still says "SNI block" while
Optimize is on. In the Tauri build, a check run while Optimize is on also tries each
host through the proxy and adds **Optimize ✓** or **Optimize ✗** to its row; the
summary then says how many sites get through Optimize.

**DNS mode** (`src-tauri/src/dnsmode.rs`, `src/scripts/dns.ps1`). Sets the active
adapter (the one owning the best default route) to Google, OpenDNS, AdGuard,
Alibaba or Cloudflare, registers DNS-over-HTTPS on Windows 11, and saves the
original servers so Undo restores them. One UAC prompt per change. Both builds run
the same `dns.ps1`.

**Optimize** (`src-tauri/src/proxy.rs` + `tls.rs`, `src/lib/fragproxy.js` + `tls.js`).
A local HTTP proxy on `127.0.0.1:18787`, set as the Windows system proxy while it
runs. Each TLS ClientHello it forwards is split into two records sent as separate
TCP segments, so the host name never appears whole in one packet. Destination names
are resolved over DoH, so DNS poisoning doesn't affect it either. "Find best split"
tries each split method in order and keeps the first one that completes a handshake.

**Language.** The UI is in Vietnamese by default; the **EN / VI** button in the
header switches language and the choice is remembered. All UI text lives in
`src/renderer/i18n.js`, which also translates the backends' English messages
(notes, errors, log lines). `test/i18n.test.js` checks both languages have every
key the UI uses.

## Project layout

```
src/renderer/          UI shared by both builds
  bridge.js            maps window.fugawrap onto Tauri commands (no-op in Electron)
src/scripts/dns.ps1    DNS mode script, used by both builds
src-tauri/             Tauri build
  src/lib.rs           commands, app state, startup recovery, cleanup on exit
  src/probe.rs         connection check and split measurement
  src/proxy.rs         ClientHello-splitting HTTP proxy
  src/tls.rs           ClientHello parsing and splitting
  src/doh.rs           DNS-over-HTTPS and the proxy's resolver
  src/dnsmode/         DNS mode: windows.rs (runs dns.ps1 elevated), macos.rs
  src/sysproxy/        system proxy backup and recovery: windows.rs, macos.rs
  src/ps.rs            PowerShell runner (scripts passed in memory, Windows)
  src/mac.rs           networksetup and admin-prompt helpers (macOS)
  src/settings.rs      settings file
  tauri.conf.json      window, CSP, bundle settings
src/main.js, src/preload.js, src/lib/   Electron build
test/                  Node tests
scripts/               live-check.js, make-icons.js
```

## macOS

The Tauri build runs on macOS with the same UI and check. Differences:

- **Optimize** (`src-tauri/src/sysproxy/macos.rs`) sets the HTTP and HTTPS proxy
  of every enabled network service with `networksetup`, adds local addresses to
  the bypass list and turns off any auto-proxy (PAC) URL while it runs. The
  previous settings of each service are saved and restored the same way as on
  Windows. Admin users don't get a password prompt for this.
- **DNS mode** (`src-tauri/src/dnsmode/macos.rs`) sets plain DNS servers on the
  service that owns the default route (e.g. Wi-Fi). macOS only turns on
  DNS-over-HTTPS through configuration profiles, so there's no DoH here. It tries
  without a password first and falls back to the administrator password prompt.
  Undo puts back the old servers, or "automatic" (DHCP) if none were set.
- If browsing breaks after a crash while Optimize was on, start FugaWrap again,
  or run `networksetup -setwebproxystate Wi-Fi off; networksetup -setsecurewebproxystate Wi-Fi off`.

## Debugging the Tauri build

- **UI:** in `npm run tauri:dev`, right-click → **Inspect** (or Ctrl+Shift+I) opens
  DevTools. Ctrl+R reloads after editing `src/renderer/`. Backend commands can be
  called from the console, e.g. `await window.fugawrap.diagnose()`.
- **Release exe UI:** start it with
  `$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS='--remote-debugging-port=9333'`, then
  open `edge://inspect` in Edge.
- **Rust:** `eprintln!` output and panics appear in the `tauri:dev` terminal; set
  `$env:RUST_BACKTRACE='1'` for stack traces. Release builds have no console.
  For breakpoints, use VS Code with the C/C++ extension (`cppvsdbg`) on
  `src-tauri/target/debug/fugawrap.exe`.
- **Live network tests** (opt-in, hit real servers):
  `cargo test --manifest-path src-tauri/Cargo.toml -- --ignored --nocapture live_`
  prints DoH answers and repeats each handshake three times per split method.

Where state lives:

| What | Where |
|---|---|
| Settings, proxy backup (Tauri) | `%APPDATA%\shop.fungamingvn.fugawrap\` |
| Settings, proxy backup (Electron) | `%APPDATA%\FugaWrap\` |
| DNS mode state and log | `C:\ProgramData\FugaWrap\dns-state.json`, `dns.log` |
| Settings, proxy backup, DNS state (macOS) | `~/Library/Application Support/shop.fungamingvn.fugawrap/` |

If browsing breaks after a crash while Optimize was on, start FugaWrap again (it
repairs the proxy setting on startup) or run:
`Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' ProxyEnable 0`