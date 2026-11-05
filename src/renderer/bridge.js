'use strict';
// Tauri build: provide the same window.fugawrap API that the Electron preload
// exposes, so renderer.js runs unchanged in both. Does nothing under Electron.
(() => {
  if (window.fugawrap || !window.__TAURI__) return;
  const { invoke } = window.__TAURI__.core;
  const { listen } = window.__TAURI__.event;

  // Commands reject with an error string; the UI expects { ok, value | error }.
  const call = (cmd, argName) => async (arg) => {
    try {
      return { ok: true, value: await invoke(cmd, argName ? { [argName]: arg ?? null } : {}) };
    } catch (e) {
      return { ok: false, error: String(e) };
    }
  };
  const on = (event) => (fn) => {
    const unlisten = listen(event, (e) => fn(e.payload));
    return () => { unlisten.then((off) => off()); };
  };

  window.fugawrap = {
    getSettings: call('get_settings'),
    setTargets: call('set_targets', 'targets'),
    diagnose: call('diagnose'),
    dnsStatus: call('dns_status'),
    dnsSet: call('dns_set', 'provider'),
    dnsRestore: call('dns_restore'),
    optimizeStatus: call('optimize_status'),
    optimizeStart: call('optimize_start'),
    optimizeStop: call('optimize_stop'),
    optimizeMeasure: call('optimize_measure', 'host'),
    onProgress: on('diagnose:progress'),
    onLog: on('log'),
  };
})();
