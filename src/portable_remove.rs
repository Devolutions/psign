use crate::CommandOutput;
use crate::cli::{GlobalOpts, RemoveArgs};
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use std::path::Path;

pub fn remove_command(args: &RemoveArgs, global: &GlobalOpts) -> Result<CommandOutput> {
    if !args.strip_signature
        || args.strip_chain_except_signer
        || args.strip_unauthenticated_attributes
    {
        return Err(anyhow!(
            "portable remove supports only --strip-signature (/s); partial embedded CMS removal (/c or /u) requires Windows mode"
        ));
    }

    let mut output = String::new();
    for path in &args.files {
        let ext = extension_lower(path);
        let removed = if is_pe_winmd_extension(&ext) {
            remove_pe_signature(path)?
        } else if psign_sip_digest::ps_script::extension_supported(&ext) {
            remove_powershell_signature(path, &ext)?
        } else {
            return Err(anyhow!(
                "portable remove supports PE/WinMD and PowerShell Authenticode scripts (.ps1, .psd1, .psm1, .ps1xml, .psc1, .cdxml, .mof); got {}",
                path.display()
            ));
        };

        if !global.quiet {
            if removed {
                output.push_str(&format!(
                    "Removed embedded Authenticode data from {}\n",
                    path.display()
                ));
            } else {
                output.push_str(&format!(
                    "No embedded Authenticode data found in {}\n",
                    path.display()
                ));
            }
        }
    }
    Ok(CommandOutput::ok(output))
}

fn remove_pe_signature(path: &Path) -> Result<bool> {
    let bytes = std::fs::read(path).with_context(|| format!("read '{}'", path.display()))?;
    let (unsigned, removed_count) =
        psign_sip_digest::pe_embed::pe_remove_authenticode_certificates(bytes).with_context(
            || {
                format!(
                    "remove PE/WinMD Authenticode signature from '{}'",
                    path.display()
                )
            },
        )?;
    if removed_count > 0 {
        std::fs::write(path, unsigned)
            .with_context(|| format!("write unsigned PE/WinMD '{}'", path.display()))?;
    }
    Ok(removed_count > 0)
}

fn remove_powershell_signature(path: &Path, ext: &str) -> Result<bool> {
    let bytes = std::fs::read(path).with_context(|| format!("read '{}'", path.display()))?;
    let (content, encoding) = ScriptEncoding::decode(&bytes)
        .with_context(|| format!("decode PowerShell script '{}'", path.display()))?;
    let Some(unsigned) = remove_script_signature_block(&content, ext) else {
        return Ok(false);
    };
    std::fs::write(path, encoding.encode(&unsigned))
        .with_context(|| format!("write unsigned PowerShell script '{}'", path.display()))?;
    Ok(true)
}

fn remove_script_signature_block(content: &str, ext: &str) -> Option<String> {
    let (begin, end) = match ext {
        "ps1xml" | "psc1" | "cdxml" => (
            "<!-- SIG # Begin signature block -->",
            "<!-- SIG # End signature block -->",
        ),
        "mof" => (
            "/* SIG # Begin signature block */",
            "/* SIG # End signature block */",
        ),
        _ => (
            "# SIG # Begin signature block",
            "# SIG # End signature block",
        ),
    };
    let begin_at = content.rfind(begin)?;
    let end_at = content[begin_at + begin.len()..].find(end)? + begin_at + begin.len();
    let after_end = end_at + end.len();
    if !content[after_end..].trim().is_empty()
        || !is_authenticode_signature_block(&content[begin_at + begin.len()..end_at], ext)
    {
        return None;
    }
    let mut remove_start = begin_at;
    if content[..begin_at].ends_with("\r\n") {
        remove_start -= 2;
    } else if content[..begin_at].ends_with('\n') {
        remove_start -= 1;
    }
    let mut remove_end = after_end;
    if content[remove_end..].starts_with("\r\n") {
        remove_end += 2;
    } else if content[remove_end..].starts_with('\n') {
        remove_end += 1;
    }
    let mut unsigned = String::with_capacity(content.len() - (remove_end - remove_start));
    unsigned.push_str(&content[..remove_start]);
    unsigned.push_str(&content[remove_end..]);
    Some(unsigned)
}

fn is_authenticode_signature_block(body: &str, ext: &str) -> bool {
    let mut payload = String::new();
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let encoded = match ext {
            "ps1xml" | "psc1" | "cdxml" => line
                .strip_prefix("<!-- ")
                .and_then(|line| line.strip_suffix(" -->")),
            "mof" => line
                .strip_prefix("/* ")
                .and_then(|line| line.strip_suffix(" */")),
            _ => line.strip_prefix("# "),
        };
        let Some(encoded) = encoded else {
            return false;
        };
        payload.push_str(encoded);
    }
    if payload.is_empty() {
        return false;
    }
    base64::engine::general_purpose::STANDARD
        .decode(payload)
        .is_ok()
}

#[derive(Clone, Copy)]
enum ScriptEncoding {
    Utf8 { bom: bool },
    Utf16Le,
    Utf16Be,
}

impl ScriptEncoding {
    fn decode(bytes: &[u8]) -> Result<(String, Self)> {
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Ok((
                String::from_utf8(bytes[3..].to_vec()).context("invalid UTF-8 with BOM")?,
                Self::Utf8 { bom: true },
            ));
        }
        if bytes.starts_with(&[0xFF, 0xFE]) {
            return Ok((decode_utf16(&bytes[2..], true)?, Self::Utf16Le));
        }
        if bytes.starts_with(&[0xFE, 0xFF]) {
            return Ok((decode_utf16(&bytes[2..], false)?, Self::Utf16Be));
        }
        Ok((
            String::from_utf8(bytes.to_vec()).context("invalid UTF-8 script")?,
            Self::Utf8 { bom: false },
        ))
    }

    fn encode(self, content: &str) -> Vec<u8> {
        match self {
            Self::Utf8 { bom } => {
                let mut bytes = Vec::with_capacity(content.len() + usize::from(bom) * 3);
                if bom {
                    bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
                }
                bytes.extend_from_slice(content.as_bytes());
                bytes
            }
            Self::Utf16Le => encode_utf16(content, true, [0xFF, 0xFE]),
            Self::Utf16Be => encode_utf16(content, false, [0xFE, 0xFF]),
        }
    }
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(anyhow!("UTF-16 script has an odd byte length"));
    }
    let words = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();
    String::from_utf16(&words).context("invalid UTF-16 script")
}

fn encode_utf16(content: &str, little_endian: bool, bom: [u8; 2]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + content.len() * 2);
    bytes.extend_from_slice(&bom);
    for word in content.encode_utf16() {
        let encoded = if little_endian {
            word.to_le_bytes()
        } else {
            word.to_be_bytes()
        };
        bytes.extend_from_slice(&encoded);
    }
    bytes
}

fn extension_lower(path: &Path) -> String {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default()
}

fn is_pe_winmd_extension(extension: &str) -> bool {
    matches!(extension, "exe" | "dll" | "sys" | "ocx" | "efi" | "winmd")
}

#[cfg(test)]
mod tests {
    use super::{is_authenticode_signature_block, remove_script_signature_block};

    #[test]
    fn removes_script_signature_and_its_surrounding_newline() {
        let signed = "Write-Output test\r\n# SIG # Begin signature block\r\n# YWJj\r\n# SIG # End signature block\r\n";
        assert!(is_authenticode_signature_block("\r\n# YWJj\r\n", "ps1"));
        assert_eq!(
            remove_script_signature_block(signed, "ps1"),
            Some("Write-Output test".to_string())
        );
    }

    #[test]
    fn removes_xml_and_mof_signature_blocks() {
        assert_eq!(
            remove_script_signature_block(
                "<root />\n<!-- SIG # Begin signature block -->\n<!-- YWJj -->\n<!-- SIG # End signature block -->\n",
                "ps1xml"
            ),
            Some("<root />".to_string())
        );
        assert_eq!(
            remove_script_signature_block(
                "instance of x {}\n/* SIG # Begin signature block */\n/* YWJj */\n/* SIG # End signature block */\n",
                "mof"
            ),
            Some("instance of x {}".to_string())
        );
    }

    #[test]
    fn does_not_remove_nonterminal_or_non_cms_marker_blocks() {
        let source = "# SIG # Begin signature block\nnot-a-signature\n# SIG # End signature block\nWrite-Output test\n";
        assert_eq!(remove_script_signature_block(source, "ps1"), None);
    }
}
