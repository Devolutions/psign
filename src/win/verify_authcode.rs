//! Authenticode metadata for `verify /d` (`SPC_SP_OPUS_INFO`) and page-hash presence for `verify /ph`.
use std::ffi::CStr;
use std::mem::size_of;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Cryptography::{
    CERT_QUERY_ENCODING_TYPE, CMSG_SIGNER_INFO, CRYPT_ATTRIBUTES, CryptDecodeObject,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{
    SPC_FILE_LINK_CHOICE, SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID, SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID,
    SPC_SP_OPUS_INFO, SPC_SP_OPUS_INFO_OBJID, SPC_SP_OPUS_INFO_STRUCT, SPC_URL_LINK_CHOICE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
};

const PKCS7_X509: CERT_QUERY_ENCODING_TYPE =
    CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);

fn pwstr_to_string(p: windows::core::PCWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut out = Vec::new();
    // SAFETY: `p` is a NUL-terminated wide string from decoded WinTrust / crypt32 structures.
    unsafe {
        let mut i = 0;
        loop {
            let w = *p.0.add(i);
            if w == 0 {
                break;
            }
            out.push(w);
            i += 1;
        }
    }
    String::from_utf16_lossy(&out)
}

fn attr_oid_matches(psz_obj_id: windows::core::PSTR, expected: windows::core::PCSTR) -> bool {
    if psz_obj_id.is_null() {
        return false;
    }
    let attr = unsafe { CStr::from_ptr(psz_obj_id.0.cast()) };
    let exp = unsafe { CStr::from_ptr(expected.0.cast()) };
    attr == exp
}

/// Strip one outer DER OCTET STRING wrapper when present (common for PKCS#9 auth attributes).
fn octet_string_payload(d: &[u8]) -> Option<&[u8]> {
    if d.len() < 2 || d[0] != 0x04 {
        return None;
    }
    let (len, hdr) = der_len_and_header(&d[1..])?;
    let start = 1 + hdr;
    let end = start.checked_add(len)?;
    d.get(start..end)
}

fn der_len_and_header(d: &[u8]) -> Option<(usize, usize)> {
    if d.is_empty() {
        return None;
    }
    let first = d[0] as usize;
    if first & 0x80 == 0 {
        return Some((first, 1));
    }
    let n = first & 0x7f;
    if n == 0 || n > 4 || d.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | d[1 + i] as usize;
    }
    Some((len, 1 + n))
}

fn try_decode_spc_opus(blob: &[u8]) -> Option<(String, Option<String>)> {
    let mut candidates: Vec<&[u8]> = vec![blob];
    if let Some(inner) = octet_string_payload(blob) {
        candidates.push(inner);
    }
    for candidate in candidates {
        if candidate.is_empty() {
            continue;
        }
        let mut cb = 0u32;
        // SAFETY: size query; `pcbstructinfo` receives required buffer size.
        let r = unsafe {
            CryptDecodeObject(
                PKCS7_X509,
                SPC_SP_OPUS_INFO_STRUCT,
                candidate,
                0,
                None,
                &mut cb,
            )
        };
        if r.is_err() || cb == 0 {
            continue;
        }
        let mut buf = vec![0u8; cb as usize];
        // SAFETY: buffer sized by prior CryptDecodeObject call.
        let r2 = unsafe {
            CryptDecodeObject(
                PKCS7_X509,
                SPC_SP_OPUS_INFO_STRUCT,
                candidate,
                0,
                Some(buf.as_mut_ptr().cast()),
                &mut cb,
            )
        };
        if r2.is_err() {
            continue;
        }
        buf.truncate(cb as usize);
        if buf.len() < size_of::<SPC_SP_OPUS_INFO>() {
            continue;
        }
        // SAFETY: `CryptDecodeObject` filled `buf` with an `SPC_SP_OPUS_INFO`; pointers aim into `buf`.
        let opus = unsafe { &*(buf.as_ptr().cast::<SPC_SP_OPUS_INFO>()) };
        let name = pwstr_to_string(opus.pwszProgramName);
        let url = if opus.pMoreInfo.is_null() {
            None
        } else {
            // SAFETY: `pMoreInfo` is a valid `SPC_LINK` when non-null per decoded struct.
            unsafe {
                let link = &*opus.pMoreInfo;
                match link.dwLinkChoice {
                    SPC_URL_LINK_CHOICE => {
                        let p = link.Anonymous.pwszUrl;
                        let s = pwstr_to_string(windows::core::PCWSTR(p.0));
                        if s.is_empty() { None } else { Some(s) }
                    }
                    SPC_FILE_LINK_CHOICE => {
                        let p = link.Anonymous.pwszFile;
                        let s = pwstr_to_string(windows::core::PCWSTR(p.0));
                        if s.is_empty() { None } else { Some(s) }
                    }
                    _ => None,
                }
            }
        };
        return Some((name, url));
    }
    None
}

fn sp_opus_from_signer_info(signer: *const CMSG_SIGNER_INFO) -> Option<(String, Option<String>)> {
    if signer.is_null() {
        return None;
    }
    // SAFETY: `signer` points at a valid `CMSG_SIGNER_INFO` from WinTrust provider data.
    let auth = unsafe { &(*signer).AuthAttrs };
    if auth.cAttr == 0 || auth.rgAttr.is_null() {
        return None;
    }
    for i in 0..auth.cAttr {
        // SAFETY: `rgAttr` has `cAttr` elements.
        let attr = unsafe { &*auth.rgAttr.add(i as usize) };
        if !attr_oid_matches(attr.pszObjId, SPC_SP_OPUS_INFO_OBJID) {
            continue;
        }
        for j in 0..attr.cValue {
            // SAFETY: `rgValue` has `cValue` elements.
            let blob = unsafe { &*attr.rgValue.add(j as usize) };
            let slice = if blob.cbData == 0 || blob.pbData.is_null() {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }
            };
            if let Some(r) = try_decode_spc_opus(slice) {
                return Some(r);
            }
        }
    }
    None
}

/// Read SPC_SP_OPUS_INFO for the given signer index from an open WinVerifyTrust state handle.
pub fn sp_opus_from_wvt_state(
    hstate: HANDLE,
    signer_index: u32,
) -> Option<(String, Option<String>)> {
    if hstate.is_invalid() {
        return None;
    }
    // SAFETY: `hstate` is a WinVerifyTrust state data handle before `WTD_STATEACTION_CLOSE`.
    let pprov = unsafe { WTHelperProvDataFromStateData(hstate) };
    if pprov.is_null() {
        return None;
    }
    // SAFETY: `WTHelperGetProvSignerFromChain` returns a signer record for valid provider data.
    let sgnr = unsafe { WTHelperGetProvSignerFromChain(pprov, signer_index, false, 0) };
    if sgnr.is_null() {
        return None;
    }
    let ps = unsafe { (*sgnr).psSigner };
    sp_opus_from_signer_info(ps)
}

/// Native-style `Description:` / `Description URL:` lines (see `signtool verify /v /d` output).
pub fn format_verify_description_lines(name: &str, url: Option<&str>) -> String {
    // Align with `signtool verify /v /d` (SDK): padded program name, single space before URL value.
    let mut s = format!("Description:     {name}\n");
    if let Some(u) = url
        && !u.is_empty()
    {
        s.push_str(&format!("Description URL: {u}\n"));
    }
    s
}

fn attrs_contain_pe_page_hash_oid(attrs: &CRYPT_ATTRIBUTES) -> bool {
    if attrs.cAttr == 0 || attrs.rgAttr.is_null() {
        return false;
    }
    for i in 0..attrs.cAttr {
        let attr = unsafe { &*attrs.rgAttr.add(i as usize) };
        if attr_oid_matches(attr.pszObjId, SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID)
            || attr_oid_matches(attr.pszObjId, SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID)
        {
            return true;
        }
    }
    false
}

/// True if the signer PKCS#7 carries PE page-hash attributes (V1 or V2 OID).
pub fn pe_image_page_hashes_present_from_signer_info(signer: *const CMSG_SIGNER_INFO) -> bool {
    if signer.is_null() {
        return false;
    }
    let u = unsafe { &(*signer).UnauthAttrs };
    let a = unsafe { &(*signer).AuthAttrs };
    attrs_contain_pe_page_hash_oid(u) || attrs_contain_pe_page_hash_oid(a)
}

/// Whether page-hash attributes are present for the given signer index (WinVerifyTrust state).
pub fn pe_image_page_hashes_present_from_wvt_state(hstate: HANDLE, signer_index: u32) -> bool {
    if hstate.is_invalid() {
        return false;
    }
    let pprov = unsafe { WTHelperProvDataFromStateData(hstate) };
    if pprov.is_null() {
        return false;
    }
    let sgnr = unsafe { WTHelperGetProvSignerFromChain(pprov, signer_index, false, 0) };
    if sgnr.is_null() {
        return false;
    }
    let ps = unsafe { (*sgnr).psSigner };
    pe_image_page_hashes_present_from_signer_info(ps)
}
