'use strict';
// Run the connection check and strategy measurement from the command line,
// without Electron. Usage: node scripts/live-check.js [host ...]
const { diagnose, measureStrategy } = require('../src/lib/diagnose');
const { describeStrategy } = require('../src/lib/tls');

const hosts = process.argv.slice(2);
const targets = hosts.length ? hosts : ['store.steampowered.com', 'api.steampowered.com', 'steamcommunity.com'];

(async () => {
  const report = await diagnose(targets);
  for (const r of report.targets) {
    console.log(`${r.host.padEnd(28)} ${r.kind.padEnd(4)} ${r.note}`);
    console.log(`  system DNS: ${r.sysIps.join(', ') || '-'}   DoH: ${r.dohIps.join(', ') || '-'}`);
    for (const s of r.steps) console.log(`  ${s.ok ? 'ok  ' : 'FAIL'} ${s.step}${s.strategy ? ` [${describeStrategy(s.strategy)}]` : ''} ${s.ms ?? ''}ms ${s.error || ''}`);
  }
  console.log(`\nsummary: ${report.kind || 'no blocking'}; recommend: ${report.recommend || 'nothing'}`);
  const m = await measureStrategy(targets[0]);
  console.log(`best split for ${targets[0]}: ${describeStrategy(m.strategy)} (${m.tried.length} tried)`);
})();
