'use strict';
// Run PowerShell scripts without writing them to disk.
//
// RevoltWarp drops its .ps1 files into C:\ProgramData\RevoltWarp, a folder every
// local user can write to, then runs them as administrator. Here the script text
// goes over stdin (normal) or inside -EncodedCommand (elevated), so there is no
// file another user could swap out.

const { spawn } = require('child_process');

const READ_STDIN = '& ([scriptblock]::Create([Console]::In.ReadToEnd()))';

function runPs(script, { timeoutMs = 60000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', READ_STDIN],
      { windowsHide: true });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('PowerShell timed out')); }, timeoutMs);
    child.stdout.setEncoding('utf8').on('data', (d) => { stdout += d; });
    child.stderr.setEncoding('utf8').on('data', (d) => { stderr += d; });
    child.once('error', (e) => { clearTimeout(timer); reject(e); });
    child.once('close', (code) => { clearTimeout(timer); resolve({ code, stdout: stdout.trim(), stderr: stderr.trim() }); });
    child.stdin.end(script, 'utf8');
  });
}

// Run a script as administrator through a UAC prompt. Output from the elevated
// process cannot be captured, so scripts report through their exit code and log.
async function runPsElevated(script, { timeoutMs = 120000 } = {}) {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const launcher = `
try {
  $p = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop \`
       -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','${encoded}'
  exit $p.ExitCode
} catch { exit 1223 }`;
  const r = await runPs(launcher, { timeoutMs });
  if (r.code === 1223) throw new Error('Administrator permission was declined');
  return r;
}

// Quote a value for a single-quoted PowerShell string.
const psQuote = (s) => `'${String(s).replace(/'/g, "''")}'`;

module.exports = { runPs, runPsElevated, psQuote };
