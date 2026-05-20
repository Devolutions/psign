//! Grow the PE attribute certificate table with an additional **`WIN_CERTIFICATE`** wrapping PKCS#7 (**Authenticode**).
//!
//! This module performs **file layout only**: it does **not** build a valid CMS **`SignedData`**, re-hash the PE for signing,
//! or match **`SignerSignEx3`** output byte-for-byte. **`pe_append_authenticode_pkcs7_certificate`** does refresh **`CheckSum`**
//! (**`pe_compute_image_checksum`**) after mutation. It exists so Linux-side tooling
//! can experiment with **multi-signature** placement and so future portable signers can call into a single embed helper.
//!
//! **Layout** matches the Windows **`WIN_CERTIFICATE`** record produced by **`repack_pkcs_signed_win_certificate`** in the Windows-only
//! **`psign`** crate (**`src/win/remove_unauth.rs`**): little-endian **`dwLength`**, **`wRevision`**, **`wCertificateType`**, then PKCS#7 DER;
//! the total size is padded with zero bytes to a multiple of **8**; **`dwLength`** covers the full padded record.

use anyhow::{Result, anyhow};

/// `WIN_CERT_REVISION_2_0` (0x0200) — used by modern Authenticode signatures.
const WIN_CERT_REVISION_2_0: u16 = 0x0200;

/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA` (0x0002).
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

const PE_OFFSET: usize = 0x3c;
const PE32_MAGIC: u16 = 0x10b;
const PE32PLUS_MAGIC: u16 = 0x20b;

const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

/// Byte offset from the start of the optional header to **`CheckSum`** (** DWORD**, PE32 and PE32+).
const OPTIONAL_HEADER_CHECKSUM_OFFSET: usize = 64;

fn pe_checksum_field_file_offset(pe: &[u8]) -> Result<usize> {
    let (optional_start, _) = pe_optional_header_start(pe)?;
    let off = optional_start + OPTIONAL_HEADER_CHECKSUM_OFFSET;
    if off + 4 > pe.len() {
        return Err(anyhow!(
            "PE image truncated before Optional Header CheckSum"
        ));
    }
    Ok(off)
}

/// Compute the PE **image checksum** (Windows **`CheckSumMappedFile`** / PE loader style).
///
/// The **`CheckSum`** field itself is treated as **zero** during the 16-bit_word accumulation; the low 16 bits are folded until
/// **`≤ 0xffff`**, then **`image.len()`** (**`u32`**) is added (wrapping).
pub fn pe_compute_image_checksum(image: &[u8]) -> Result<u32> {
    let check_off = pe_checksum_field_file_offset(image)?;
    let mut sum: u64 = 0;
    let mut i = 0usize;
    while i < image.len() {
        if i >= check_off && i < check_off + 4 {
            i = check_off + 4;
            continue;
        }
        if i + 1 < image.len() {
            sum += u64::from(u16::from_le_bytes([image[i], image[i + 1]]));
        } else {
            sum += u64::from(image[i]);
        }
        sum = (sum >> 16) + (sum & 0xffff);
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    Ok((sum as u32).wrapping_add(image.len() as u32))
}

/// Write **`checksum`** to the optional header **`CheckSum`** field (**little-endian**).
pub fn pe_write_image_checksum(image: &mut [u8], checksum: u32) -> Result<()> {
    let off = pe_checksum_field_file_offset(image)?;
    image[off..off + 4].copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

/// Read **`Optional Header.CheckSum`** (**little-endian**) without validating it.
pub fn pe_read_image_checksum(image: &[u8]) -> Result<u32> {
    let off = pe_checksum_field_file_offset(image)?;
    Ok(u32::from_le_bytes(image[off..off + 4].try_into().map_err(
        |_| anyhow!("PE optional header CheckSum field truncated"),
    )?))
}

fn pe_refresh_image_checksum(image: &mut [u8]) -> Result<()> {
    let c = pe_compute_image_checksum(image)?;
    pe_write_image_checksum(image, c)?;
    debug_assert_eq!(
        pe_compute_image_checksum(image).expect("recompute checksum"),
        c
    );
    Ok(())
}

/// Wrap **raw PKCS#7** (**`SignedData`**) bytes in a **`WIN_CERTIFICATE`** with **padding to 8-byte alignment** (Windows layout).
pub fn wrap_pkcs7_der_authenticode_win_certificate(pkcs7_der: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + pkcs7_der.len() + 8);
    body.resize(8 + pkcs7_der.len(), 0);
    body[4..6].copy_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
    body[6..8].copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    body[8..].copy_from_slice(pkcs7_der);
    while body.len() % 8 != 0 {
        body.push(0);
    }
    let total = body.len() as u32;
    body[0..4].copy_from_slice(&total.to_le_bytes());
    body
}

fn pe_optional_header_start(pe: &[u8]) -> Result<(usize, u16)> {
    if pe.len() < PE_OFFSET + 4 {
        return Err(anyhow!("PE image too small"));
    }
    if pe.get(0..2) != Some(&[0x4d, 0x5a]) {
        return Err(anyhow!("missing MZ DOS stub"));
    }
    let pe_off = u32::from_le_bytes(pe[PE_OFFSET..PE_OFFSET + 4].try_into().unwrap()) as usize;
    if pe_off + 24 > pe.len() {
        return Err(anyhow!("invalid e_lfanew"));
    }
    if pe.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return Err(anyhow!("missing PE signature"));
    }
    let optional_start = pe_off + 4 + 20;
    if optional_start + 2 > pe.len() {
        return Err(anyhow!("truncated optional header"));
    }
    let magic = u16::from_le_bytes(pe[optional_start..optional_start + 2].try_into().unwrap());
    Ok((optional_start, magic))
}

fn data_directory_entry_offset(optional_start: usize, magic: u16) -> Result<usize> {
    let dir0 = match magic {
        PE32_MAGIC => optional_start + 96,
        PE32PLUS_MAGIC => optional_start + 112,
        _ => return Err(anyhow!("unsupported optional header magic {magic:#x}")),
    };
    Ok(dir0 + IMAGE_DIRECTORY_ENTRY_SECURITY * 8)
}

fn number_of_rva_and_sizes_offset(optional_start: usize, magic: u16) -> Result<usize> {
    match magic {
        PE32_MAGIC => Ok(optional_start + 92),
        PE32PLUS_MAGIC => Ok(optional_start + 108),
        _ => Err(anyhow!("unsupported optional header magic {magic:#x}")),
    }
}

fn read_security_data_directory(pe: &[u8]) -> Result<(u32, u32)> {
    let (optional_start, magic) = pe_optional_header_start(pe)?;
    let num_rva_off = number_of_rva_and_sizes_offset(optional_start, magic)?;
    if num_rva_off + 4 > pe.len() {
        return Err(anyhow!("truncated NumberOfRvaAndSizes"));
    }
    let num = u32::from_le_bytes(pe[num_rva_off..num_rva_off + 4].try_into().unwrap()) as usize;
    if num <= IMAGE_DIRECTORY_ENTRY_SECURITY {
        return Err(anyhow!(
            "PE optional header has only {num} data directories (need security slot)"
        ));
    }
    let dd_off = data_directory_entry_offset(optional_start, magic)?;
    if dd_off + 8 > pe.len() {
        return Err(anyhow!("truncated security data directory"));
    }
    let va = u32::from_le_bytes(pe[dd_off..dd_off + 4].try_into().unwrap());
    let size = u32::from_le_bytes(pe[dd_off + 4..dd_off + 8].try_into().unwrap());
    Ok((va, size))
}

fn write_security_data_directory(pe: &mut [u8], cert_file_ptr: u32, cert_size: u32) -> Result<()> {
    let (optional_start, magic) = pe_optional_header_start(pe)?;
    let dd_off = data_directory_entry_offset(optional_start, magic)?;
    if dd_off + 8 > pe.len() {
        return Err(anyhow!("truncated security data directory (write)"));
    }
    pe[dd_off..dd_off + 4].copy_from_slice(&cert_file_ptr.to_le_bytes());
    pe[dd_off + 4..dd_off + 8].copy_from_slice(&cert_size.to_le_bytes());
    Ok(())
}

/// Append **`pkcs7_der`** as a new **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** row after the existing attribute certificate table.
///
/// - When the security directory is **empty** (**`VirtualAddress`** and **`Size`** are zero), the blob is appended at the **current EOF**
///   and the directory is initialized (**`VirtualAddress`** is the **file offset** to the table for PE files).
/// - When a table **already exists**, new bytes are appended immediately after **`VirtualAddress + Size`**; the file is truncated
///   first if it is longer than that end offset (defensive).
///
/// **`Optional Header.CheckSum`** is recomputed after changes (**`pe_compute_image_checksum`**).
pub fn pe_append_authenticode_pkcs7_certificate(
    mut pe_image: Vec<u8>,
    pkcs7_der: &[u8],
) -> Result<Vec<u8>> {
    let wrapped = wrap_pkcs7_der_authenticode_win_certificate(pkcs7_der);
    let (va, size) = read_security_data_directory(&pe_image)?;
    if va == 0 && size == 0 {
        let off = pe_image.len() as u32;
        pe_image.extend_from_slice(&wrapped);
        write_security_data_directory(&mut pe_image, off, wrapped.len() as u32)?;
        pe_refresh_image_checksum(&mut pe_image)?;
        return Ok(pe_image);
    }
    let start = va as usize;
    let end = start
        .checked_add(size as usize)
        .ok_or_else(|| anyhow!("security directory size overflow"))?;
    if start > pe_image.len() {
        return Err(anyhow!(
            "security directory pointer {start} past EOF {}",
            pe_image.len()
        ));
    }
    if end < pe_image.len() {
        pe_image.truncate(end);
    } else if end > pe_image.len() {
        return Err(anyhow!(
            "security directory end {end} beyond EOF {}",
            pe_image.len()
        ));
    }
    pe_image.extend_from_slice(&wrapped);
    let new_size = size
        .checked_add(wrapped.len() as u32)
        .ok_or_else(|| anyhow!("certificate table size overflow"))?;
    write_security_data_directory(&mut pe_image, va, new_size)?;
    pe_refresh_image_checksum(&mut pe_image)?;
    Ok(pe_image)
}

/// Replace the **`pkcs7_index`**-th `WIN_CERT_TYPE_PKCS_SIGNED_DATA` row in the PE certificate table.
///
/// This is used by portable post-sign mutation flows such as timestamp insertion. The certificate table is
/// rebuilt at the same file offset, PE bytes after the old table are discarded, the security directory size is
/// updated, and `Optional Header.CheckSum` is recomputed.
pub fn pe_replace_authenticode_pkcs7_certificate_at(
    mut pe_image: Vec<u8>,
    pkcs7_index: usize,
    pkcs7_der: &[u8],
) -> Result<Vec<u8>> {
    let replacement = wrap_pkcs7_der_authenticode_win_certificate(pkcs7_der);
    let (va, size) = read_security_data_directory(&pe_image)?;
    if va == 0 || size == 0 {
        return Err(anyhow!("PE has no certificate table"));
    }
    let start = va as usize;
    let end = start
        .checked_add(size as usize)
        .ok_or_else(|| anyhow!("security directory size overflow"))?;
    if start > pe_image.len() || end > pe_image.len() {
        return Err(anyhow!(
            "security directory range {start}..{end} is outside PE length {}",
            pe_image.len()
        ));
    }

    let table = pe_image[start..end].to_vec();
    let mut rebuilt = Vec::with_capacity(table.len() + replacement.len());
    let mut offset = 0usize;
    let mut pkcs7_seen = 0usize;
    let mut replaced = false;
    while offset < table.len() {
        if offset + 8 > table.len() {
            return Err(anyhow!(
                "truncated WIN_CERTIFICATE header at table offset {offset}"
            ));
        }
        let len = u32::from_le_bytes(table[offset..offset + 4].try_into().unwrap()) as usize;
        if len < 8 || offset + len > table.len() {
            return Err(anyhow!(
                "invalid WIN_CERTIFICATE length {len} at table offset {offset}"
            ));
        }
        let cert_type = u16::from_le_bytes(table[offset + 6..offset + 8].try_into().unwrap());
        if cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            if pkcs7_seen == pkcs7_index {
                rebuilt.extend_from_slice(&replacement);
                replaced = true;
            } else {
                rebuilt.extend_from_slice(&table[offset..offset + len]);
            }
            pkcs7_seen += 1;
        } else {
            rebuilt.extend_from_slice(&table[offset..offset + len]);
        }
        offset += len;
    }
    if !replaced {
        return Err(anyhow!(
            "no PKCS#7 Authenticode entry at index {pkcs7_index} (found {pkcs7_seen})"
        ));
    }

    pe_image.truncate(start);
    pe_image.extend_from_slice(&rebuilt);
    write_security_data_directory(&mut pe_image, va, rebuilt.len() as u32)?;
    pe_refresh_image_checksum(&mut pe_image)?;
    Ok(pe_image)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs7::{
        encode_pkcs7_content_info_signed_data_der, parse_pe_pkcs7_spc_indirect_data,
        parse_pe_pkcs7_spc_indirect_data_at, parse_pkcs7_signed_data_der,
        signed_data_replace_encapsulated_spc_indirect, signed_data_replace_first_signer_info,
        spc_indirect_data_replace_message_digest,
    };
    use crate::verify_pe::{
        pe_nth_pkcs7_signed_data_der, pe_pkcs7_signed_data_entry_count,
        verify_pe_authenticode_digest_consistency,
    };

    #[test]
    fn win_certificate_wrap_length_is_multiple_of_eight() {
        let pkcs7 =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let der = pe_nth_pkcs7_signed_data_der(pkcs7, 0).expect("pkcs7");
        let w = wrap_pkcs7_der_authenticode_win_certificate(&der);
        assert!(
            w.len().is_multiple_of(8),
            "dwLength domain includes 8-byte alignment"
        );
        assert!(w.len() >= 8);
        let dw = u32::from_le_bytes(w[0..4].try_into().unwrap()) as usize;
        assert_eq!(dw, w.len());
        assert_eq!(
            u16::from_le_bytes(w[4..6].try_into().unwrap()),
            WIN_CERT_REVISION_2_0
        );
        assert_eq!(
            u16::from_le_bytes(w[6..8].try_into().unwrap()),
            WIN_CERT_TYPE_PKCS_SIGNED_DATA
        );
    }

    #[test]
    fn append_reencoded_pkcs7_row_matches_spc_indirect_and_checksum() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
                .as_slice();
        let row0 = pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("row0 pkcs7");
        let sd = parse_pkcs7_signed_data_der(&row0).expect("SignedData");
        let reencoded = encode_pkcs7_content_info_signed_data_der(&sd).expect("reencode");

        let indirect0 = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("indirect 0");
        let out = pe_append_authenticode_pkcs7_certificate(pe_bytes.to_vec(), reencoded.as_slice())
            .expect("append reencoded");
        assert_eq!(pe_pkcs7_signed_data_entry_count(&out).unwrap(), 2);
        assert_eq!(
            pe_nth_pkcs7_signed_data_der(&out, 0).unwrap(),
            row0,
            "first WIN_CERTIFICATE row unchanged"
        );

        let indirect1 =
            parse_pe_pkcs7_spc_indirect_data_at(&out, 1).expect("indirect from appended row");
        assert_eq!(
            indirect0, indirect1,
            "cms re-encode must preserve Authenticode SpcIndirectDataContent"
        );

        let row1 = pe_nth_pkcs7_signed_data_der(&out, 1).expect("row1");
        let row1_pkcs7 = crate::pkcs7_wire::pkcs7_outer_sequence_prefix(&row1)
            .expect("row1 PKCS#7 SEQUENCE prefix");
        let re_norm = crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode(&reencoded);
        assert_eq!(
            row1_pkcs7,
            re_norm.as_ref(),
            "appended row must match normalized re-encoded PKCS#7 bytes"
        );

        let chk = pe_compute_image_checksum(&out).expect("checksum");
        let off = pe_checksum_field_file_offset(&out).expect("chk off");
        assert_eq!(
            chk,
            u32::from_le_bytes(out[off..off + 4].try_into().unwrap())
        );
    }

    #[test]
    fn append_pkcs7_after_first_signer_splice_preserves_spc_and_checksum() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
                .as_slice();
        let row0 = pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("row0 pkcs7");
        let sd = parse_pkcs7_signed_data_der(&row0).expect("SignedData");
        let si0 = sd
            .signer_infos
            .0
            .as_slice()
            .first()
            .expect("SignerInfo")
            .clone();
        let sd_spliced = signed_data_replace_first_signer_info(&sd, si0).expect("splice identity");
        assert_eq!(sd, sd_spliced);
        let reencoded = encode_pkcs7_content_info_signed_data_der(&sd_spliced).expect("reencode");

        let indirect0 = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("indirect 0");
        let out = pe_append_authenticode_pkcs7_certificate(pe_bytes.to_vec(), reencoded.as_slice())
            .expect("append after splice");

        assert_eq!(pe_pkcs7_signed_data_entry_count(&out).unwrap(), 2);
        assert_eq!(
            pe_nth_pkcs7_signed_data_der(&out, 0).unwrap(),
            row0,
            "first WIN_CERTIFICATE row unchanged"
        );
        let indirect1 =
            parse_pe_pkcs7_spc_indirect_data_at(&out, 1).expect("indirect from appended row");
        assert_eq!(indirect0, indirect1);

        let chk = pe_compute_image_checksum(&out).expect("checksum");
        let off = pe_checksum_field_file_offset(&out).expect("chk off");
        assert_eq!(
            chk,
            u32::from_le_bytes(out[off..off + 4].try_into().unwrap())
        );
    }

    #[test]
    fn append_pkcs7_with_flipped_indirect_triggers_verify_pe_digest_mismatch() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
                .as_slice();
        verify_pe_authenticode_digest_consistency(pe_bytes).expect("fixture consistent");

        let pkcs7 = pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("indirect");
        let mut flipped_digest = indirect.message_digest.digest.as_bytes().to_vec();
        flipped_digest[0] ^= 0xff;
        let flipped =
            spc_indirect_data_replace_message_digest(&indirect, &flipped_digest).expect("flip");
        let sd_bad =
            signed_data_replace_encapsulated_spc_indirect(&sd, &flipped).expect("mut encap");
        let blob = encode_pkcs7_content_info_signed_data_der(&sd_bad).expect("encode PKCS#7");

        let out = pe_append_authenticode_pkcs7_certificate(pe_bytes.to_vec(), blob.as_slice())
            .expect("append PKCS#7 whose indirect digest does not match PE image");
        let err = verify_pe_authenticode_digest_consistency(&out).expect_err("digest gate");
        assert!(
            err.to_string().contains("mismatch"),
            "expected SIP mismatch message, got {err:?}"
        );
    }

    #[test]
    fn append_duplicate_pkcs7_increments_embedded_row_count() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
                .as_slice();
        assert_eq!(pe_pkcs7_signed_data_entry_count(pe_bytes).unwrap(), 1);
        let row0_before = pe_nth_pkcs7_signed_data_der(pe_bytes, 0).unwrap();
        let pkcs7_der = crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode(&row0_before);
        let pkcs7_der = pkcs7_der.as_ref();
        let out =
            pe_append_authenticode_pkcs7_certificate(pe_bytes.to_vec(), pkcs7_der).expect("append");
        assert_eq!(pe_pkcs7_signed_data_entry_count(&out).unwrap(), 2);
        assert_eq!(
            pe_nth_pkcs7_signed_data_der(&out, 0).unwrap(),
            row0_before,
            "first WIN_CERTIFICATE row must be unchanged"
        );
        let row1 = pe_nth_pkcs7_signed_data_der(&out, 1).unwrap();
        let row1_pkcs7 = crate::pkcs7_wire::pkcs7_outer_sequence_prefix(&row1)
            .expect("second row should begin with PKCS#7 SEQUENCE");
        assert_eq!(
            row1_pkcs7, pkcs7_der,
            "second row must wrap the same PKCS#7 bytes"
        );
        let chk = pe_compute_image_checksum(&out).expect("checksum");
        let off = pe_checksum_field_file_offset(&out).expect("chk off");
        assert_eq!(
            chk,
            u32::from_le_bytes(out[off..off + 4].try_into().unwrap())
        );
    }

    #[test]
    fn tiny32_signed_fixture_checksum_matches_embedded_header() {
        let pe =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
                .as_slice();
        let stored = pe_read_image_checksum(pe).unwrap();
        assert_eq!(pe_compute_image_checksum(pe).unwrap(), stored);
    }

    #[test]
    fn tiny64_signed_fixture_checksum_matches_embedded_header() {
        let pe =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi")
                .as_slice();
        let stored = pe_read_image_checksum(pe).unwrap();
        assert_eq!(pe_compute_image_checksum(pe).unwrap(), stored);
    }
}
