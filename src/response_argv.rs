//! Expand native `signtool @responsefile` argument lists (see `signtool-help-root.txt`).
//!
//! When the executable is invoked as `psign-tool @path`, the file is read: one argument per
//! line, optional blank line between command blocks (multiple invocations). Otherwise, any
//! tail argument starting with a single `@` is treated as a response path and spliced. A
//! leading `@@` is not a splice: one `@` is stripped so the argument can start with `@`.
//!
//! A line may be wrapped in double quotes so a single argument can contain spaces; `""` inside
//! quotes becomes one literal `"` (common native response-file style).
//!
//! Response bodies may be **UTF-8**, **UTF-8 with BOM**, or **UTF-16 LE/BE with BOM** (as MSVC
//! often writes). If bytes are not valid UTF-8, they are interpreted as **UTF-16 LE** without BOM.
//!
//! When **splicing** inline `@path` tokens, a leading `@@` strips one `@` so a literal argument
//! can begin with `@` (e.g. `--f @@\\\\server\\share\\cert.pfx`).

use anyhow::{Context, Result, anyhow};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_RESPONSE_DEPTH: u32 = 8;
const MAX_RESPONSE_LINES: usize = 4096;

fn is_response_path_arg(arg: &OsString) -> Option<PathBuf> {
    let s = arg.to_string_lossy();
    let rest = s.strip_prefix('@')?;
    if rest.is_empty() || s.starts_with("@@") {
        return None;
    }
    Some(PathBuf::from(rest))
}

fn utf16_bytes_to_string(bytes: &[u8], big_endian: bool) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(anyhow!(
            "response file UTF-16 payload has odd length ({} bytes)",
            bytes.len()
        ));
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let u = if big_endian {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from_le_bytes([pair[0], pair[1]])
        };
        units.push(u);
    }
    String::from_utf16(&units).map_err(|e| anyhow!("response file UTF-16 decode failed: {}", e))
}

fn read_response_text(path: &Path) -> Result<String> {
    let mut bytes =
        fs::read(path).with_context(|| format!("reading response file {}", path.display()))?;
    if bytes.len() >= 3 && bytes[0..3] == [0xEF, 0xBB, 0xBF] {
        bytes.drain(..3);
        return String::from_utf8(bytes).map_err(|e| {
            anyhow!(
                "response file {} is not valid UTF-8 after BOM strip: {}",
                path.display(),
                e
            )
        });
    }
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        bytes.drain(..2);
        return utf16_bytes_to_string(&bytes, false);
    }
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        bytes.drain(..2);
        return utf16_bytes_to_string(&bytes, true);
    }
    match String::from_utf8(bytes) {
        Ok(s) => Ok(s),
        Err(e) => {
            let utf8_err = e.utf8_error();
            let raw = e.into_bytes();
            utf16_bytes_to_string(&raw, false).map_err(|e2| {
                anyhow!(
                    "response file {}: invalid UTF-8 ({}); UTF-16-LE fallback failed: {}",
                    path.display(),
                    utf8_err,
                    e2
                )
            })
        }
    }
}

/// Trim Windows `\r` and surrounding whitespace; empty lines become `""` after trim for block splitting.
fn normalized_line(line: &str) -> String {
    line.trim_end_matches('\r').trim().to_string()
}

/// One response-file token may be wrapped in double quotes; doubled quotes inside represent a literal `"`.
fn decode_response_arg_token(line: &str) -> String {
    let t = line.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        let inner = &t[1..t.len() - 1];
        inner.replace("\"\"", "\"")
    } else {
        t.to_string()
    }
}

fn append_response_line(out: &mut Vec<String>, raw_line: &str, depth: u32) -> Result<()> {
    let t = normalized_line(raw_line);
    if t.is_empty() {
        return Ok(());
    }
    let decoded = decode_response_arg_token(&t);
    if let Some(inner) = decoded.strip_prefix('@').filter(|s| !s.is_empty()) {
        out.extend(read_flat_args_from_file(Path::new(inner), depth + 1)?);
    } else {
        out.push(decoded);
    }
    Ok(())
}

fn read_flat_args_from_file(path: &Path, depth: u32) -> Result<Vec<String>> {
    if depth > MAX_RESPONSE_DEPTH {
        return Err(anyhow!(
            "response file nesting exceeds {MAX_RESPONSE_DEPTH} (@-includes are too deep)"
        ));
    }
    let text = read_response_text(path)?;
    let mut out = Vec::new();
    let mut lines_seen = 0usize;
    for line in text.lines() {
        lines_seen += 1;
        if lines_seen > MAX_RESPONSE_LINES {
            return Err(anyhow!(
                "response file {} exceeds {MAX_RESPONSE_LINES} lines",
                path.display()
            ));
        }
        append_response_line(&mut out, line, depth)?;
    }
    Ok(out)
}

/// Split into command blocks separated by one or more empty lines (native `signtool` behavior).
fn parse_multi_command_blocks(text: &str) -> Result<Vec<Vec<String>>> {
    let mut blocks: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut lines_seen = 0usize;

    for line in text.lines() {
        lines_seen += 1;
        if lines_seen > MAX_RESPONSE_LINES {
            return Err(anyhow!("response file exceeds {MAX_RESPONSE_LINES} lines"));
        }
        if normalized_line(line).is_empty() {
            if !current.is_empty() {
                blocks.push(std::mem::take(&mut current));
            }
            continue;
        }
        append_response_line(&mut current, line, 0)?;
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    if blocks.is_empty() {
        return Err(anyhow!("response file is empty (no arguments)"));
    }
    Ok(blocks)
}

fn prepend_executable(executable: &OsString, tail: Vec<String>) -> Vec<OsString> {
    let mut v = Vec::with_capacity(1 + tail.len());
    v.push(executable.clone());
    v.extend(tail.into_iter().map(OsString::from));
    v
}

/// Build one or more full argv vectors (each begins with `executable`).
///
/// `tail` is `std::env::args_os().skip(1)` (everything after the program path).
pub fn expand_invocations(executable: OsString, tail: Vec<OsString>) -> Result<Vec<Vec<OsString>>> {
    // Classic: `psign-tool @file` — multi-block response file (blank line between commands).
    if tail.len() == 1
        && let Some(path) = is_response_path_arg(&tail[0])
    {
        let text = read_response_text(&path)?;
        let blocks = parse_multi_command_blocks(&text)?;
        return Ok(blocks
            .into_iter()
            .map(|b| prepend_executable(&executable, b))
            .collect());
    }

    // General: splice every `@path` token in the tail into separate arguments (one invocation).
    let mut out: Vec<OsString> = Vec::with_capacity(1 + tail.len());
    out.push(executable.clone());
    for arg in tail {
        let s = arg.to_string_lossy();
        if s.starts_with("@@") {
            if s.len() == 2 {
                out.push(OsString::from("@"));
            } else {
                out.push(OsString::from(s[1..].to_string()));
            }
            continue;
        }
        if let Some(path) = is_response_path_arg(&arg) {
            let flat = read_flat_args_from_file(&path, 0)?;
            out.extend(flat.into_iter().map(OsString::from));
        } else {
            out.push(arg);
        }
    }
    Ok(vec![out])
}

/// Combine exit codes like a batch: any hard failure wins; else Azure HRESULT-style outcomes; else any warning.
pub fn combine_batch_exit_codes(acc: i32, next: i32) -> i32 {
    use crate::{AZURE_SIGN_EXIT_ALL_FAILED, AZURE_SIGN_EXIT_PARTIAL_SUCCESS};
    if acc == 1 || next == 1 {
        return 1;
    }
    if acc == AZURE_SIGN_EXIT_ALL_FAILED || next == AZURE_SIGN_EXIT_ALL_FAILED {
        return AZURE_SIGN_EXIT_ALL_FAILED;
    }
    if acc == AZURE_SIGN_EXIT_PARTIAL_SUCCESS || next == AZURE_SIGN_EXIT_PARTIAL_SUCCESS {
        return AZURE_SIGN_EXIT_PARTIAL_SUCCESS;
    }
    if acc == 2 || next == 2 { 2 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn expands_at_file_to_extra_args() {
        let dir = std::env::temp_dir();
        let inner = dir.join("psign_rsp_inner.txt");
        fs::write(&inner, "/pa\n").expect("write inner");
        let rsp = dir.join("psign_rsp_outer.txt");
        fs::write(&rsp, format!("verify\n@{}\nx.exe\n", inner.display())).expect("write rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec!["psign-tool", "verify", "/pa", "x.exe",]
        );
        let _ = fs::remove_file(&inner);
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn at_only_form_two_command_blocks() {
        let dir = std::env::temp_dir();
        let rsp = dir.join("psign_rsp_multiblock.txt");
        fs::write(&rsp, "verify\n/pa\na.exe\n\nsign\n/fd\nSHA256\nb.exe\n").expect("write");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 2);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec!["psign-tool", "verify", "/pa", "a.exe",]
        );
        assert_eq!(
            inv[1]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec!["psign-tool", "sign", "/fd", "SHA256", "b.exe",]
        );
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn combine_codes() {
        use crate::{AZURE_SIGN_EXIT_ALL_FAILED, AZURE_SIGN_EXIT_PARTIAL_SUCCESS};
        assert_eq!(combine_batch_exit_codes(0, 2), 2);
        assert_eq!(combine_batch_exit_codes(2, 0), 2);
        assert_eq!(combine_batch_exit_codes(2, 1), 1);
        assert_eq!(combine_batch_exit_codes(0, 1), 1);
        assert_eq!(combine_batch_exit_codes(0, 0), 0);
        assert_eq!(
            combine_batch_exit_codes(0, AZURE_SIGN_EXIT_PARTIAL_SUCCESS),
            AZURE_SIGN_EXIT_PARTIAL_SUCCESS
        );
        assert_eq!(
            combine_batch_exit_codes(AZURE_SIGN_EXIT_PARTIAL_SUCCESS, AZURE_SIGN_EXIT_ALL_FAILED),
            AZURE_SIGN_EXIT_ALL_FAILED
        );
        assert_eq!(
            combine_batch_exit_codes(AZURE_SIGN_EXIT_PARTIAL_SUCCESS, 1),
            1
        );
    }

    #[test]
    fn decode_response_arg_token_quotes() {
        assert_eq!(decode_response_arg_token("  plain  "), "plain");
        assert_eq!(
            decode_response_arg_token(r#""C:\Program Files\app.exe""#),
            r"C:\Program Files\app.exe"
        );
        assert_eq!(
            decode_response_arg_token(r#""say ""hi"" today""#),
            r#"say "hi" today"#
        );
    }

    #[test]
    fn response_file_quoted_path_single_argument() {
        let dir = std::env::temp_dir();
        let spaced = dir.join("psign_rsp spaced target.exe");
        fs::write(&spaced, b"0").expect("write target");
        let rsp = dir.join("psign_rsp_quoted_path.txt");
        fs::write(
            &rsp,
            format!("verify\n--policy\npa\n\"{}\"\n", spaced.to_string_lossy()),
        )
        .expect("write rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        let argv: Vec<String> = inv[0]
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "--policy".to_string(),
                "pa".to_string(),
                spaced.to_string_lossy().into_owned(),
            ]
        );
        let _ = fs::remove_file(&spaced);
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn response_file_quoted_include_path() {
        let dir = std::env::temp_dir();
        let inner_name = "signtool rs inner inc.txt";
        let inner = dir.join(inner_name);
        fs::write(&inner, "/pa\n").expect("write inner");
        let rsp = dir.join("psign_rsp_quote_include.txt");
        fs::write(
            &rsp,
            format!("verify\n\"@{}\"\nx.exe\n", inner.to_string_lossy()),
        )
        .expect("write rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        let argv: Vec<String> = inv[0]
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "/pa".to_string(),
                "x.exe".to_string(),
            ]
        );
        let _ = fs::remove_file(&inner);
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn response_file_utf16_le_bom_roundtrip() {
        let dir = std::env::temp_dir();
        let rsp = dir.join("psign_rsp_utf16le_bom.rsp");
        let text = "verify\n/pa\nx.exe\n";
        let mut raw: Vec<u8> = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            raw.extend_from_slice(&u.to_le_bytes());
        }
        fs::write(&rsp, &raw).expect("write utf-16 rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "/pa".to_string(),
                "x.exe".to_string(),
            ]
        );
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn response_file_utf16_be_bom_roundtrip() {
        let dir = std::env::temp_dir();
        let rsp = dir.join("psign_rsp_utf16be_bom.rsp");
        let text = "verify\n/pa\ny.exe\n";
        let mut raw: Vec<u8> = vec![0xFE, 0xFF];
        for u in text.encode_utf16() {
            raw.extend_from_slice(&u.to_be_bytes());
        }
        fs::write(&rsp, &raw).expect("write utf-16be rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "/pa".to_string(),
                "y.exe".to_string(),
            ]
        );
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn response_file_utf8_bom_roundtrip() {
        let dir = std::env::temp_dir();
        let rsp = dir.join("psign_rsp_utf8_bom.rsp");
        let body = "verify\n/pa\nz.exe\n";
        let mut raw = vec![0xEFu8, 0xBB, 0xBF];
        raw.extend_from_slice(body.as_bytes());
        fs::write(&rsp, &raw).expect("write utf-8 bom rsp");

        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from(format!("@{}", rsp.display()))],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        assert_eq!(
            inv[0]
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "/pa".to_string(),
                "z.exe".to_string(),
            ]
        );
        let _ = fs::remove_file(&rsp);
    }

    #[test]
    fn inline_double_at_strips_one_at_for_literal() {
        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![
                OsString::from("sign"),
                OsString::from("y.exe"),
                OsString::from("--f"),
                OsString::from("@@C:/certs/spaced name.pfx"),
            ],
        )
        .expect("expand");
        assert_eq!(inv.len(), 1);
        let argv: Vec<String> = inv[0]
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "psign-tool".to_string(),
                "sign".to_string(),
                "y.exe".to_string(),
                "--f".to_string(),
                "@C:/certs/spaced name.pfx".to_string(),
            ]
        );
    }

    #[test]
    fn inline_double_at_only_is_single_at_token() {
        let exe = OsString::from("psign-tool");
        let inv = expand_invocations(
            exe.clone(),
            vec![OsString::from("verify"), OsString::from("@@")],
        )
        .expect("expand");
        let argv: Vec<String> = inv[0]
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            vec![
                "psign-tool".to_string(),
                "verify".to_string(),
                "@".to_string(),
            ]
        );
    }
}
