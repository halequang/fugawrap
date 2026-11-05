'use strict';
const { contextBridge, ipcRenderer } = require('electron');

const call = (channel) => (...args) => ipcRenderer.invoke(channel, ...args);
const on = (channel) => (fn) => {
  const listener = (_e, payload) => fn(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.off(channel, listener);
};

contextBridge.exposeInMainWorld('netfix', {
  getSettings: call('settings:get'),
  setTargets: call('settings:targets'),
  diagnose: call('diagnose'),
  dnsStatus: call('dns:status'),
  dnsSet: call('dns:set'),
  dnsRestore: call('dns:restore'),
  optimizeStatus: call('optimize:status'),
  optimizeStart: call('optimize:start'),
  optimizeStop: call('optimize:stop'),
  optimizeMeasure: call('optimize:measure'),
  onProgress: on('diagnose:progress'),
  onLog: on('log'),
});
