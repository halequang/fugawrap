//! Run PowerShell scripts without writing them to disk.
//!
//! The script text goes over stdin (normal) or inside -EncodedCommand (elevated)
//! instead of into a .ps1 file, so there is no file another local user could swap
//! out before it runs as administrator.

use base64::Engine;
use std::io::{self, Write};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const READ_STDIN: &str = "& ([scriptblock]::Create([Console]::In.ReadToEnd()))";
/// Exit code the launcher uses when the UAC prompt is declined.
const UAC_DECLINED: i32 = 1223;

pub struct PsOutput {
    pub code: i32,
    pub stdout: String,
}

pub fn run_ps(script: &str) -> io::Result<PsOutput> {
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", READ_STDIN])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;
    child.stdin.take().expect("piped stdin").write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    Ok(PsOutput {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).trim().to_string(),
    })
}

/// Run a script as administrator through a UAC prompt. Output from the elevated
/// process cannot be captured, so scripts report through their exit code and log.
pub fn run_ps_elevated(script: &str) -> Result<PsOutput, String> {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let launcher = format!(
        "try {{
  $p = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop `
       -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','{encoded}'
  exit $p.ExitCode
}} catch {{ exit {UAC_DECLINED} }}"
    );
    let r = run_ps(&launcher).map_err(|e| e.to_string())?;
    if r.code == UAC_DECLINED {
        return Err("Administrator permission was declined".into());
    }
    Ok(r)
}

/// Quote a value for a single-quoted PowerShell string.
pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
