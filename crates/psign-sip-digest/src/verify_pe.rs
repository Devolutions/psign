use super::pe_digest::{ParsedPe, PeAuthenticodeHashKind, pe_authenticode_digest};
use anyhow::{Result, anyhow};
use authenticode::{AttributeCertificateIterator, WIN_CERT_TYPE_PKCS_SIGNED_DATA};

#[derive(Debug, Clone)]
pub struct PeDigestConsistencyResult {
    pub recomputed_digest_hex: String,
    pub matched_attribute_certificate_index: usize,
    pub pkcs7_authenticode_entries: usize,
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Ensure every PKCS#7 Authenticode attribute certificate's indirect digest matches the Rust PE image digest
/// for the inferred hash algorithm (from embedded digest length).
pub fn verify_pe_authenticode_digest_consistency(
    bytes: &[u8],
) -> Result<PeDigestConsistencyResult> {
    let parsed = ParsedPe::parse(bytes)?;
    let pe = parsed.as_pe_trait();
    let Some(iter) = AttributeCertificateIterator::new(pe)
        .map_err(|e| anyhow!("certificate table invalid: {e}"))?
    else {
        return Err(anyhow!("PE has no certificate table"));
    };

    let mut pkcs7_count = 0usize;
    let mut last_hex = String::new();
    let mut last_idx = 0usize;

    for (idx, entry) in iter.enumerate() {
        let attr = entry.map_err(|e| anyhow!("attribute certificate entry invalid: {e}"))?;
        if attr.certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            continue;
        }
        let sig = attr
            .get_authenticode_signature()
            .map_err(|e| anyhow!("PKCS#7 Authenticode parse failed: {e}"))?;
        pkcs7_count += 1;
        let embedded = sig.digest();
        let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded.len())?;
        let computed = pe_authenticode_digest(bytes, kind)?;
        if computed.as_slice() != embedded {
            return Err(anyhow!(
                "Rust SIP digest mismatch for PKCS#7 entry {idx}: recomputed {} vs embedded {}",
                hex_lower(&computed),
                hex_lower(embedded)
            ));
        }
        last_hex = hex_lower(&computed);
        last_idx = idx;
    }

    if pkcs7_count == 0 {
        return Err(anyhow!(
            "no PKCS#7 Authenticode entries found in certificate table"
        ));
    }

    Ok(PeDigestConsistencyResult {
        recomputed_digest_hex: last_hex,
        matched_attribute_certificate_index: last_idx,
        pkcs7_authenticode_entries: pkcs7_count,
    })
}

/// Invoke `f(index, pkcs7_der)` for each `WIN_CERT_TYPE_PKCS_SIGNED_DATA` attribute certificate.
///
/// Returns how many PKCS#7 blobs were visited. Fails if the PE has no certificate table or no PKCS#7 entries.
pub fn for_each_pe_pkcs7_signed_data(
    bytes: &[u8],
    mut f: impl FnMut(usize, &[u8]) -> Result<()>,
) -> Result<usize> {
    let parsed = ParsedPe::parse(bytes)?;
    let pe = parsed.as_pe_trait();
    let Some(iter) = AttributeCertificateIterator::new(pe)
        .map_err(|e| anyhow!("certificate table invalid: {e}"))?
    else {
        return Err(anyhow!("PE has no certificate table"));
    };

    let mut pkcs7_count = 0usize;
    for (idx, entry) in iter.enumerate() {
        let attr = entry.map_err(|e| anyhow!("attribute certificate entry invalid: {e}"))?;
        if attr.certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            continue;
        }
        f(idx, attr.data)?;
        pkcs7_count += 1;
    }

    if pkcs7_count == 0 {
        return Err(anyhow!(
            "no PKCS#7 Authenticode entries found in certificate table"
        ));
    }

    Ok(pkcs7_count)
}

/// PKCS#7 **`SignedData`** bytes from the **`index`**-th **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** attribute certificate (**`0`** = first), certificate-table order.
///
/// For errors when **`index`** is out of range, see [`pe_pkcs7_signed_data_entry_count`].
pub fn pe_nth_pkcs7_signed_data_der(pe_image: &[u8], index: usize) -> Result<Vec<u8>> {
    let parsed = ParsedPe::parse(pe_image)?;
    let pe = parsed.as_pe_trait();
    let Some(iter) = AttributeCertificateIterator::new(pe)
        .map_err(|e| anyhow!("certificate table invalid: {e}"))?
    else {
        return Err(anyhow!("PE has no certificate table"));
    };
    let mut skip = index;
    for entry in iter {
        let attr = entry.map_err(|e| anyhow!("attribute certificate entry invalid: {e}"))?;
        if attr.certificate_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            if skip == 0 {
                return Ok(attr.data.to_vec());
            }
            skip -= 1;
        }
    }
    Err(anyhow!(
        "no PKCS#7 Authenticode entry at index {index} (fewer PKCS#7 rows in certificate table)"
    ))
}

/// PKCS#7 **`SignedData`** bytes from the **first** **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** attribute certificate (same as **`index`** **`0`**).
///
/// For multi-signed PEs, use [`pe_nth_pkcs7_signed_data_der`] or [`for_each_pe_pkcs7_signed_data`].
pub fn pe_first_pkcs7_signed_data_der(pe_image: &[u8]) -> Result<Vec<u8>> {
    pe_nth_pkcs7_signed_data_der(pe_image, 0)
}

/// Byte length of each **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** blob in certificate-table order (**`extract-pe-pkcs7 --index i`** matches **`i`** here).
///
/// Fails when there is **no** certificate table.
pub fn pe_pkcs7_signed_data_byte_lens(pe_image: &[u8]) -> Result<Vec<usize>> {
    let parsed = ParsedPe::parse(pe_image)?;
    let pe = parsed.as_pe_trait();
    let Some(iter) = AttributeCertificateIterator::new(pe)
        .map_err(|e| anyhow!("certificate table invalid: {e}"))?
    else {
        return Err(anyhow!("PE has no certificate table"));
    };
    let mut lens = Vec::new();
    for entry in iter {
        let attr = entry.map_err(|e| anyhow!("attribute certificate entry invalid: {e}"))?;
        if attr.certificate_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            lens.push(attr.data.len());
        }
    }
    Ok(lens)
}

/// Count of **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** rows in the PE certificate table (**`0`** if there is a table but no PKCS#7 entries).
///
/// Fails when there is **no** certificate table.
pub fn pe_pkcs7_signed_data_entry_count(pe_image: &[u8]) -> Result<usize> {
    Ok(pe_pkcs7_signed_data_byte_lens(pe_image)?.len())
}

#[cfg(test)]
mod pe_first_pkcs7_tests {
    use super::*;

    #[test]
    fn first_pkcs7_starts_with_sequence_on_tiny_fixture() {
        let bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let der = pe_first_pkcs7_signed_data_der(bytes).expect("extract pkcs7");
        assert!(
            der.len() > 128,
            "expected non-trivial PKCS#7 payload on signed fixture"
        );
        assert_eq!(der.first().copied(), Some(0x30));
    }

    #[test]
    fn nth_zero_matches_first_on_tiny_fixture() {
        let bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let a = pe_first_pkcs7_signed_data_der(bytes).unwrap();
        let b = pe_nth_pkcs7_signed_data_der(bytes, 0).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn entry_count_is_one_on_tiny_fixture() {
        let bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        assert_eq!(pe_pkcs7_signed_data_entry_count(bytes).unwrap(), 1);
        let lens = pe_pkcs7_signed_data_byte_lens(bytes).unwrap();
        assert_eq!(lens.len(), 1);
        assert_eq!(
            lens[0],
            pe_first_pkcs7_signed_data_der(bytes).unwrap().len()
        );
    }

    #[test]
    fn second_pkcs7_index_errors_on_single_signed_fixture() {
        let bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        assert!(pe_nth_pkcs7_signed_data_der(bytes, 1).is_err());
    }
}
