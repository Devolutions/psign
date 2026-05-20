//! PE **Authenticode image** digest: same byte ranges as Windows **`imagehlp.dll`**
//! **[`ImageGetDigestStream`](https://learn.microsoft.com/en-us/windows/win32/api/imagehlp/nf-imagehlp-imagegetdigeststream)** (implemented here through **`authenticode-rs`**).
use anyhow::{Result, anyhow};
use authenticode::{PeOffsetError, PeTrait, authenticode_digest};
use digest::Digest;
use object::read::FileKind;
use object::read::pe::{PeFile32, PeFile64};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use std::ops::Range;

/// Supported Authenticode PE image digest algorithms for recomputation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeAuthenticodeHashKind {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl PeAuthenticodeHashKind {
    pub fn from_digest_byte_len(len: usize) -> Result<Self> {
        match len {
            20 => Ok(Self::Sha1),
            32 => Ok(Self::Sha256),
            48 => Ok(Self::Sha384),
            64 => Ok(Self::Sha512),
            _ => Err(anyhow!(
                "unsupported Authenticode digest length {len} bytes (expected 20/32/48/64)"
            )),
        }
    }

    /// Digest output size in bytes for this algorithm.
    pub fn digest_output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

pub(crate) enum ParsedPe<'a> {
    Pe32(PeFile32<'a>),
    Pe64(PeFile64<'a>),
}

impl<'a> ParsedPe<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        match FileKind::parse(bytes).map_err(|e| anyhow!("not a PE image: {e}"))? {
            FileKind::Pe32 => Ok(Self::Pe32(
                PeFile32::parse(bytes).map_err(|e| anyhow!("PE32 parse failed: {e}"))?,
            )),
            FileKind::Pe64 => Ok(Self::Pe64(
                PeFile64::parse(bytes).map_err(|e| anyhow!("PE32+ parse failed: {e}"))?,
            )),
            other => Err(anyhow!("expected PE32 or PE32+ file, got {:?}", other)),
        }
    }

    pub fn as_pe_trait(&self) -> &dyn PeTrait {
        match self {
            Self::Pe32(p) => p as &dyn PeTrait,
            Self::Pe64(p) => p as &dyn PeTrait,
        }
    }
}

/// File byte ranges that [`authenticode_digest`] hashes, **in order** (same layout as
/// [`authenticode-rs` `authenticode_digest_impl`](https://github.com/google/authenticode-rs/blob/main/authenticode/src/authenticode_digest.rs)).
///
/// Hashing the concatenation of `image[r.start..r.end]` for each range `r` yields the same digest as
/// [`pe_authenticode_digest`] for the same algorithm.
pub fn pe_authenticode_digest_file_ranges(image: &[u8]) -> Result<Vec<Range<usize>>> {
    let parsed = ParsedPe::parse(image)?;
    let pe = parsed.as_pe_trait();
    authenticode_digest_file_ranges(pe).map_err(|_| {
        anyhow!(
            "PE layout invalid for Authenticode digest ranges (checksum/security-directory offsets)"
        )
    })
}

fn authenticode_digest_file_ranges(pe: &dyn PeTrait) -> Result<Vec<Range<usize>>, PeOffsetError> {
    let offsets = pe.offsets()?;
    let mut ranges = Vec::new();
    ranges.push(0..offsets.check_sum);
    ranges.push(offsets.after_check_sum..offsets.security_data_dir);
    ranges.push(offsets.after_security_data_dir..offsets.after_header);

    let mut sum_of_bytes_hashed = offsets.after_header;

    let mut sections = (1..=pe.num_sections())
        .map(|i| pe.section_data_range(i))
        .collect::<Result<Vec<_>, _>>()?;
    sections.sort_unstable_by_key(|r| r.start);

    for section_range in sections {
        let bytes = pe.data().get(section_range.clone()).ok_or(PeOffsetError)?;
        sum_of_bytes_hashed = sum_of_bytes_hashed
            .checked_add(bytes.len())
            .ok_or(PeOffsetError)?;
        ranges.push(section_range);
    }

    let mut extra_hash_len = pe
        .data()
        .len()
        .checked_sub(sum_of_bytes_hashed)
        .ok_or(PeOffsetError)?;

    if let Some(security_data_dir) = pe.certificate_table_range()? {
        let size = security_data_dir
            .end
            .checked_sub(security_data_dir.start)
            .ok_or(PeOffsetError)?;
        extra_hash_len = extra_hash_len.checked_sub(size).ok_or(PeOffsetError)?;
    }

    let tail_end = sum_of_bytes_hashed
        .checked_add(extra_hash_len)
        .ok_or(PeOffsetError)?;
    let _ = pe
        .data()
        .get(sum_of_bytes_hashed..tail_end)
        .ok_or(PeOffsetError)?;
    ranges.push(sum_of_bytes_hashed..tail_end);

    Ok(ranges)
}

/// Return raw Authenticode digest bytes for the PE image (excludes certificate table, checksum field, etc.).
pub fn pe_authenticode_digest(bytes: &[u8], kind: PeAuthenticodeHashKind) -> Result<Vec<u8>> {
    let parsed = ParsedPe::parse(bytes)?;
    let pe = parsed.as_pe_trait();
    Ok(match kind {
        PeAuthenticodeHashKind::Sha1 => {
            let mut h = Sha1::new();
            authenticode_digest(pe, &mut h).map_err(|_| anyhow!("authenticode_digest failed"))?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha256 => {
            let mut h = Sha256::new();
            authenticode_digest(pe, &mut h).map_err(|_| anyhow!("authenticode_digest failed"))?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha384 => {
            let mut h = Sha384::new();
            authenticode_digest(pe, &mut h).map_err(|_| anyhow!("authenticode_digest failed"))?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha512 => {
            let mut h = Sha512::new();
            authenticode_digest(pe, &mut h).map_err(|_| anyhow!("authenticode_digest failed"))?;
            h.finalize().to_vec()
        }
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex SHA-256 Authenticode digest (convenience for diagnostics and tests).
pub fn pe_authenticode_digest_sha256_hex(bytes: &[u8]) -> Result<String> {
    Ok(hex_lower(&pe_authenticode_digest(
        bytes,
        PeAuthenticodeHashKind::Sha256,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_tiny32_signed_sha256_matches_upstream_authenticode_rs() {
        let pe =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let h = pe_authenticode_digest_sha256_hex(pe).unwrap();
        assert_eq!(
            h,
            "4f5b3633fc51d9447beb5c546e9ae6e58d6eb42d1e96d623dc168d97013c08a8"
        );
    }

    #[test]
    fn golden_tiny64_signed_sha256_matches_upstream_authenticode_rs() {
        let pe =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi");
        let h = pe_authenticode_digest_sha256_hex(pe).unwrap();
        assert_eq!(
            h,
            "a82d7e4f091c44ec75d97746b3461c8ea9151e2313f8e9a4330432ee5f25b2ae"
        );
    }

    #[test]
    fn random_bytes_not_pe() {
        assert!(ParsedPe::parse(b"not a pe").is_err());
    }

    #[test]
    fn digest_file_ranges_concat_matches_authenticode_digest_sha256() {
        for pe in [
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
                .as_slice(),
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi")
                .as_slice(),
        ] {
            let ranges = pe_authenticode_digest_file_ranges(pe).unwrap();
            let mut h = Sha256::new();
            for r in ranges {
                h.update(&pe[r.start..r.end]);
            }
            assert_eq!(
                h.finalize().to_vec(),
                pe_authenticode_digest(pe, PeAuthenticodeHashKind::Sha256).unwrap()
            );
        }
    }
}
