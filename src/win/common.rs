use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct NativeExecution {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn locate_signtool() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("SIGNTOOL_EXE") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    let probe = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(
            "$paths = Get-ChildItem 'C:\\Program Files (x86)\\Windows Kits\\10\\bin' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Sort-Object FullName; if ($paths) { $paths[-1].FullName }",
        )
        .output()
        .context("failed to probe Windows SDK for signtool.exe")?;

    if !probe.status.success() {
        return Err(anyhow!("unable to locate signtool.exe in Windows SDK"));
    }

    let stdout = String::from_utf8_lossy(&probe.stdout);
    let found = stdout.trim();
    if found.is_empty() {
        return Err(anyhow!(
            "signtool.exe not found; set SIGNTOOL_EXE to a full path"
        ));
    }

    Ok(PathBuf::from(found))
}

pub fn run_native_signtool_capture(args: &[String]) -> Result<NativeExecution> {
    let signtool = locate_signtool()?;

    let output = Command::new(signtool)
        .args(args)
        .output()
        .context("failed to run native signtool.exe")?;

    Ok(NativeExecution {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub fn format_native_report(run: &NativeExecution) -> String {
    let mut report = String::new();
    report.push_str("=== native signtool passthrough ===\n");
    report.push_str(&format!("exit_code={}\n", run.exit_code));
    report.push_str("--- stdout ---\n");
    report.push_str(&run.stdout);
    report.push_str("\n--- stderr ---\n");
    report.push_str(&run.stderr);
    report.push('\n');
    report
}

pub fn run_native_signtool(args: &[String]) -> Result<String> {
    let run = run_native_signtool_capture(args)?;
    let report = format_native_report(&run);
    if run.exit_code != 0 {
        return Err(anyhow!(report));
    }
    Ok(report)
}
