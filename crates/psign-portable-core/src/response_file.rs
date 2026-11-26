//! Expand native `signtool` / `psign-tool` `@responsefile` argument lists.
//!
//! When invoked with a single `@path` argument, the file is read as one argument per line, with
//! blank lines separating command blocks (multiple invocations). Otherwise, any argument starting
//! with a single `@` is treated as a response-file path and spliced into the argument vector. A
//! leading `@@` strips one `@` so a literal argument can begin with `@`.
//!
//! Lines may be wrapped in double quotes so an argument can contain spaces; `""` inside quotes
//! becomes a single literal `"`. Response files may be UTF-8, UTF-8 with BOM, UTF-16 LE/BE with
//! BOM, or UTF-16 LE without BOM when bytes are not valid UTF-8.

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
    for pair in bytes.as_chunks::<2>().0 {
        let u = if big_endian {
            u16::from_be_bytes(*pair)
        } else {
            u16::from_le_bytes(*pair)
        };
        units.push(u);
    }
    String::from_utf16(&units).map_err(|e| anyhow!("response file UTF-16 decode failed: {e}"))
}

fn read_response_text(path: &Path) -> Result<String> {
    let mut bytes =
        fs::read(path).with_context(|| format!("reading response file {}", path.display()))?;
    if bytes.len() >= 3 && bytes[0..3] == [0xEF, 0xBB, 0xBF] {
        bytes.drain(..3);
        return String::from_utf8(bytes).map_err(|e| {
            anyhow!(
                "response file {} is not valid UTF-8 after BOM strip: {e}",
                path.display()
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
                    "response file {}: invalid UTF-8 ({utf8_err}); UTF-16-LE fallback failed: {e2}",
                    path.display()
                )
            })
        }
    }
}

/// Trim Windows `\r` and surrounding whitespace; empty lines become `""` after trim for block splitting.
fn normalized_line(line: &str) -> String {
    line.trim_end_matches('\r').trim().to_string()
}

/// Decode a single response-file token line (strips outer double quotes and unescapes `""` -> `"`).
pub fn decode_response_arg_token(line: &str) -> String {
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

/// Read a response file as a flat list of arguments (ignoring blank lines and expanding nested `@` includes).
///
/// # Errors
///
/// Returns an error if the file cannot be read, encoding is invalid, or limits are exceeded.
pub fn read_response_args(path: &Path) -> Result<Vec<String>> {
    read_flat_args_from_file(path, 0)
}

/// Split response-file text into command blocks separated by one or more empty lines.
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
///
/// # Errors
///
/// Returns an error if any referenced response file cannot be read, decoded, or exceeds limits.
pub fn expand_invocations(executable: OsString, tail: Vec<OsString>) -> Result<Vec<Vec<OsString>>> {
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

    let mut out: Vec<OsString> = Vec::with_capacity(1 + tail.len());
    out.push(executable);
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

/// Expand inline `@responsefile` tokens in a list of arguments (without a leading executable name).
///
/// # Errors
///
/// Returns an error if any referenced response file cannot be read, decoded, or exceeds limits.
pub fn expand_inline_args(args: &[OsString]) -> Result<Vec<OsString>> {
    let mut out = Vec::with_capacity(args.len());
    for arg in args {
        let s = arg.to_string_lossy();
        if s.starts_with("@@") {
            if s.len() == 2 {
                out.push(OsString::from("@"));
            } else {
                out.push(OsString::from(s[1..].to_string()));
            }
            continue;
        }
        if let Some(path) = is_response_path_arg(arg) {
            let flat = read_flat_args_from_file(&path, 0)?;
            out.extend(flat.into_iter().map(OsString::from));
        } else {
            out.push(arg.clone());
        }
    }
    Ok(out)
}
