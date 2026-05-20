//! `remove /u` — strip PKCS#7 unauthenticated attributes (e.g. timestamps, dual-signature blobs)
//! via `CryptMsgControl(CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR)` and PE `Image*` certificate APIs.
//!
//! `remove /c` — drop embedding CA/chain certificates from PKCS#7 SignedData, keeping only the
//! signer certificate(s) referenced by each `SignerInfo`, via `CryptMsgControl(CMSG_CTRL_DEL_CERT)`.
//!
//! Native allows `/c` together with `/u`; both transforms run on the same decoded PKCS#7 message
//! (chain strip, then unauthenticated-attribute strip) to match native output layout.
use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Cryptography::{
    CERT_QUERY_ENCODING_TYPE, CMSG_CERT_COUNT_PARAM, CMSG_CERT_PARAM, CMSG_CTRL_DEL_CERT,
    CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR, CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA, CMSG_ENCODED_MESSAGE,
    CMSG_SIGNED, CMSG_SIGNER_COUNT_PARAM, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM,
    CRYPT_INTEGER_BLOB, CertCreateCertificateContext, CertFreeCertificateContext, CryptMsgClose,
    CryptMsgControl, CryptMsgGetParam, CryptMsgOpenToDecode, CryptMsgUpdate, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{WIN_CERT_TYPE_PKCS_SIGNED_DATA, WIN_CERTIFICATE};
use windows::Win32::System::Diagnostics::Debug::{
    CERT_SECTION_TYPE_ANY, ImageAddCertificate, ImageEnumerateCertificates,
    ImageGetCertificateData, ImageGetCertificateHeader, ImageRemoveCertificate,
};

fn der_len_and_header(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0] as usize;
    if first & 0x80 == 0 {
        return Some((first, 1));
    }
    let n = first & 0x7f;
    if n == 0 || n > 4 || data.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | data[1 + i] as usize;
    }
    Some((len, 1 + n))
}

/// Total bytes of the DER structure starting at `data[0]` (expects constructed SEQUENCE `0x30`).
fn der_constructed_total_len(data: &[u8]) -> Result<usize> {
    if data.first().copied() != Some(0x30) {
        return Err(anyhow!(
            "embedded PKCS#7 does not start with a DER SEQUENCE"
        ));
    }
    let (content_len, hdr) =
        der_len_and_header(&data[1..]).ok_or_else(|| anyhow!("invalid DER length in PKCS#7"))?;
    let total = 1 + hdr + content_len;
    if total > data.len() {
        return Err(anyhow!(
            "DER-encoded PKCS#7 length {} exceeds WIN_CERTIFICATE payload {}",
            total,
            data.len()
        ));
    }
    Ok(total)
}

fn msg_encoding_type() -> u32 {
    X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0
}

fn crypt_msg_signer_count(hmsg: *mut c_void) -> Result<u32> {
    let mut cb = 0u32;
    unsafe { CryptMsgGetParam(hmsg, CMSG_SIGNER_COUNT_PARAM, 0, None, &mut cb)? };
    if cb < 4 {
        return Err(anyhow!("unexpected CMSG_SIGNER_COUNT_PARAM size"));
    }
    let mut raw = vec![0u8; cb as usize];
    unsafe {
        CryptMsgGetParam(
            hmsg,
            CMSG_SIGNER_COUNT_PARAM,
            0,
            Some(raw.as_mut_ptr().cast()),
            &mut cb,
        )?;
    }
    Ok(u32::from_le_bytes(
        raw[0..4].try_into().map_err(|_| anyhow!("signer count"))?,
    ))
}

fn strip_unauth_attrs_from_open_msg(hmsg: *mut c_void) -> Result<()> {
    let signers = crypt_msg_signer_count(hmsg)?;
    for signer_idx in 0..signers {
        loop {
            let para = CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA {
                cbSize: size_of::<CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA>() as u32,
                dwSignerIndex: signer_idx,
                dwUnauthAttrIndex: 0,
            };
            let r = unsafe {
                CryptMsgControl(
                    hmsg,
                    0,
                    CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR,
                    Some(std::ptr::from_ref(&para).cast::<c_void>()),
                )
            };
            if r.is_err() {
                break;
            }
        }
    }
    Ok(())
}

fn crypt_msg_encoded_pkcs7(hmsg: *mut c_void) -> Result<Vec<u8>> {
    let mut cb = 0u32;
    unsafe { CryptMsgGetParam(hmsg, CMSG_ENCODED_MESSAGE, 0, None, &mut cb)? };
    if cb == 0 {
        return Err(anyhow!("CMSG_ENCODED_MESSAGE returned zero length"));
    }
    let mut out = vec![0u8; cb as usize];
    unsafe {
        CryptMsgGetParam(
            hmsg,
            CMSG_ENCODED_MESSAGE,
            0,
            Some(out.as_mut_ptr().cast()),
            &mut cb,
        )?;
    }
    out.truncate(cb as usize);
    Ok(out)
}

fn cert_encoding_type() -> CERT_QUERY_ENCODING_TYPE {
    CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0)
}

fn crypt_msg_cert_count(hmsg: *mut c_void) -> Result<u32> {
    let mut cb = 0u32;
    unsafe { CryptMsgGetParam(hmsg, CMSG_CERT_COUNT_PARAM, 0, None, &mut cb)? };
    if cb < 4 {
        return Err(anyhow!("unexpected CMSG_CERT_COUNT_PARAM size"));
    }
    let mut raw = vec![0u8; cb as usize];
    unsafe {
        CryptMsgGetParam(
            hmsg,
            CMSG_CERT_COUNT_PARAM,
            0,
            Some(raw.as_mut_ptr().cast()),
            &mut cb,
        )?;
    }
    Ok(u32::from_le_bytes(
        raw[0..4].try_into().map_err(|_| anyhow!("cert count"))?,
    ))
}

fn crypt_msg_blob_param(hmsg: *mut c_void, param: u32, index: u32) -> Result<Vec<u8>> {
    let mut cb = 0u32;
    unsafe { CryptMsgGetParam(hmsg, param, index, None, &mut cb)? };
    if cb == 0 {
        return Err(anyhow!(
            "CryptMsgGetParam({param}, {index}) returned zero length"
        ));
    }
    let mut buf = vec![0u8; cb as usize];
    unsafe {
        CryptMsgGetParam(hmsg, param, index, Some(buf.as_mut_ptr().cast()), &mut cb)?;
    }
    buf.truncate(cb as usize);
    Ok(buf)
}

fn blob_bytes(b: &CRYPT_INTEGER_BLOB) -> Result<&[u8]> {
    if b.cbData == 0 {
        return Ok(&[]);
    }
    if b.pbData.is_null() {
        return Err(anyhow!(
            "CRYPT_INTEGER_BLOB has non-zero cbData but null pbData"
        ));
    }
    Ok(unsafe { std::slice::from_raw_parts(b.pbData, b.cbData as usize) })
}

fn issuer_serial_matches_cert(cert_der: &[u8], signer: &CMSG_SIGNER_INFO) -> Result<bool> {
    let ctx = unsafe { CertCreateCertificateContext(cert_encoding_type(), cert_der) };
    if ctx.is_null() {
        return Ok(false);
    }
    // SAFETY: `ctx` from CertCreateCertificateContext; freed before return.
    unsafe {
        let info = (*ctx).pCertInfo;
        if info.is_null() {
            let _ = CertFreeCertificateContext(Some(ctx.cast_const()));
            return Ok(false);
        }
        let ci = &*info;
        let serial_ok = blob_bytes(&signer.SerialNumber)? == blob_bytes(&ci.SerialNumber)?;
        let issuer_ok = blob_bytes(&signer.Issuer)? == blob_bytes(&ci.Issuer)?;
        let _ = CertFreeCertificateContext(Some(ctx.cast_const()));
        Ok(serial_ok && issuer_ok)
    }
}

fn signer_info_ref(buf: &[u8]) -> Result<&CMSG_SIGNER_INFO> {
    if buf.len() < size_of::<CMSG_SIGNER_INFO>() {
        return Err(anyhow!(
            "CMSG_SIGNER_INFO_PARAM buffer too small ({} bytes)",
            buf.len()
        ));
    }
    // SAFETY: CryptMsgGetParam returns a decoded signer info structure; Issuer/SerialNumber blobs
    // are valid for the lifetime of `buf`.
    Ok(unsafe { &*(buf.as_ptr().cast::<CMSG_SIGNER_INFO>()) })
}

fn strip_chain_except_signer_from_open_msg(hmsg: *mut c_void) -> Result<()> {
    let cert_total = crypt_msg_cert_count(hmsg)?;
    let signer_total = crypt_msg_signer_count(hmsg)?;
    if cert_total == 0 {
        return Ok(());
    }

    let mut keep: HashSet<u32> = HashSet::new();
    for signer_idx in 0..signer_total {
        let signer_buf = crypt_msg_blob_param(hmsg, CMSG_SIGNER_INFO_PARAM, signer_idx)?;
        let signer = signer_info_ref(&signer_buf)?;
        let mut matched = false;
        for cert_idx in 0..cert_total {
            let cert_der = crypt_msg_blob_param(hmsg, CMSG_CERT_PARAM, cert_idx)?;
            if issuer_serial_matches_cert(&cert_der, signer)? {
                keep.insert(cert_idx);
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(anyhow!(
                "could not locate PKCS#7 certificate bag entry for signer index {signer_idx} (Issuer/Serial match)"
            ));
        }
    }

    let mut to_del: Vec<u32> = (0..cert_total).filter(|i| !keep.contains(i)).collect();
    to_del.sort_unstable();
    to_del.reverse();
    for idx in to_del {
        let r = unsafe {
            CryptMsgControl(
                hmsg,
                0,
                CMSG_CTRL_DEL_CERT,
                Some(std::ptr::from_ref(&idx).cast::<c_void>()),
            )
        };
        r.map_err(|e| anyhow!("CryptMsgControl(CMSG_CTRL_DEL_CERT, index={idx}) failed: {e}"))?;
    }
    Ok(())
}

fn strip_unauthenticated_attributes_pkcs7(pkcs7: &[u8]) -> Result<Vec<u8>> {
    let enc = msg_encoding_type();
    // SAFETY: crypt32 message APIs; `hmsg` closed on all paths.
    unsafe {
        let hmsg = CryptMsgOpenToDecode(enc, 0, CMSG_SIGNED.0, None, None, None);
        if hmsg.is_null() {
            return Err(anyhow!("CryptMsgOpenToDecode failed"));
        }
        let close_msg = |h: *mut c_void| {
            let _ = CryptMsgClose(Some(h));
        };
        let r_update = CryptMsgUpdate(hmsg, Some(pkcs7), true);
        if let Err(e) = r_update {
            close_msg(hmsg);
            return Err(anyhow!("CryptMsgUpdate failed: {e}"));
        }
        let r_strip = strip_unauth_attrs_from_open_msg(hmsg);
        if let Err(e) = r_strip {
            close_msg(hmsg);
            return Err(e);
        }
        let encoded = crypt_msg_encoded_pkcs7(hmsg)?;
        close_msg(hmsg);
        Ok(encoded)
    }
}

fn strip_chain_except_signer_pkcs7(pkcs7: &[u8]) -> Result<Vec<u8>> {
    let enc = msg_encoding_type();
    unsafe {
        let hmsg = CryptMsgOpenToDecode(enc, 0, CMSG_SIGNED.0, None, None, None);
        if hmsg.is_null() {
            return Err(anyhow!("CryptMsgOpenToDecode failed"));
        }
        let close_msg = |h: *mut c_void| {
            let _ = CryptMsgClose(Some(h));
        };
        let r_update = CryptMsgUpdate(hmsg, Some(pkcs7), true);
        if let Err(e) = r_update {
            close_msg(hmsg);
            return Err(anyhow!("CryptMsgUpdate failed: {e}"));
        }
        let r_strip = strip_chain_except_signer_from_open_msg(hmsg);
        if let Err(e) = r_strip {
            close_msg(hmsg);
            return Err(e);
        }
        let encoded = crypt_msg_encoded_pkcs7(hmsg)?;
        close_msg(hmsg);
        Ok(encoded)
    }
}

fn strip_chain_then_unauth_pkcs7(pkcs7: &[u8]) -> Result<Vec<u8>> {
    let enc = msg_encoding_type();
    unsafe {
        let hmsg = CryptMsgOpenToDecode(enc, 0, CMSG_SIGNED.0, None, None, None);
        if hmsg.is_null() {
            return Err(anyhow!("CryptMsgOpenToDecode failed"));
        }
        let close_msg = |h: *mut c_void| {
            let _ = CryptMsgClose(Some(h));
        };
        let r_update = CryptMsgUpdate(hmsg, Some(pkcs7), true);
        if let Err(e) = r_update {
            close_msg(hmsg);
            return Err(anyhow!("CryptMsgUpdate failed: {e}"));
        }
        if let Err(e) = strip_chain_except_signer_from_open_msg(hmsg) {
            close_msg(hmsg);
            return Err(e);
        }
        if let Err(e) = strip_unauth_attrs_from_open_msg(hmsg) {
            close_msg(hmsg);
            return Err(e);
        }
        let encoded = crypt_msg_encoded_pkcs7(hmsg)?;
        close_msg(hmsg);
        Ok(encoded)
    }
}

/// Locate outer PKCS#7 SignedData by probing `CryptMsgUpdate` (inner `SEQUENCE`s also start with `0x30`).
fn pkcs7_der_in_certificate_payload(payload: &[u8]) -> Result<&[u8]> {
    let scan_end = payload.len().min(4096);
    for off in 0..scan_end {
        if payload.get(off) != Some(&0x30) {
            continue;
        }
        let tail = &payload[off..];
        let Ok(len) = der_constructed_total_len(tail) else {
            continue;
        };
        let candidate = &tail[..len];
        if probe_pkcs7_signed_msg(candidate) {
            return Ok(candidate);
        }
    }
    Err(anyhow!(
        "could not locate decodable PKCS#7 SignedData in WIN_CERTIFICATE payload"
    ))
}

fn probe_pkcs7_signed_msg(pkcs7: &[u8]) -> bool {
    let enc = msg_encoding_type();
    unsafe {
        let hmsg = CryptMsgOpenToDecode(enc, 0, CMSG_SIGNED.0, None, None, None);
        if hmsg.is_null() {
            return false;
        }
        let ok = CryptMsgUpdate(hmsg, Some(pkcs7), true).is_ok();
        let _ = CryptMsgClose(Some(hmsg));
        ok
    }
}

fn parse_pkcs_signed_win_certificate(raw_cert: &[u8]) -> Result<Option<(u16, u16, &[u8])>> {
    if raw_cert.len() < 8 {
        return Err(anyhow!("WIN_CERTIFICATE buffer too small"));
    }
    let dw_length = u32::from_le_bytes(raw_cert[0..4].try_into().unwrap()) as usize;
    let w_revision = u16::from_le_bytes(raw_cert[4..6].try_into().unwrap());
    let w_certificate_type = u16::from_le_bytes(raw_cert[6..8].try_into().unwrap());
    if dw_length != raw_cert.len() {
        return Err(anyhow!(
            "WIN_CERTIFICATE dwLength ({dw_length}) does not match buffer ({})",
            raw_cert.len()
        ));
    }
    if w_certificate_type as u32 != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
        return Ok(None);
    }
    let payload = &raw_cert[8..dw_length];
    let pkcs_der = pkcs7_der_in_certificate_payload(payload)?;
    Ok(Some((w_revision, w_certificate_type, pkcs_der)))
}

fn repack_pkcs_signed_win_certificate(
    w_revision: u16,
    w_certificate_type: u16,
    new_pkcs: &[u8],
) -> Vec<u8> {
    let mut body = vec![0; 8 + new_pkcs.len()];
    body[4..6].copy_from_slice(&w_revision.to_le_bytes());
    body[6..8].copy_from_slice(&w_certificate_type.to_le_bytes());
    body[8..].copy_from_slice(new_pkcs);
    while !body.len().is_multiple_of(8) {
        body.push(0);
    }
    let total = body.len() as u32;
    body[0..4].copy_from_slice(&total.to_le_bytes());
    body
}

fn rebuild_pkcs_win_certificate(raw_cert: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some((rev, typ, pkcs_der)) = parse_pkcs_signed_win_certificate(raw_cert)? else {
        return Ok(None);
    };
    let new_pkcs = strip_unauthenticated_attributes_pkcs7(pkcs_der)?;
    Ok(Some(repack_pkcs_signed_win_certificate(
        rev, typ, &new_pkcs,
    )))
}

fn rebuild_pkcs_win_certificate_strip_chain(raw_cert: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some((rev, typ, pkcs_der)) = parse_pkcs_signed_win_certificate(raw_cert)? else {
        return Ok(None);
    };
    let new_pkcs = strip_chain_except_signer_pkcs7(pkcs_der)?;
    Ok(Some(repack_pkcs_signed_win_certificate(
        rev, typ, &new_pkcs,
    )))
}

fn rebuild_pkcs_win_certificate_strip_chain_and_unauth(raw_cert: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some((rev, typ, pkcs_der)) = parse_pkcs_signed_win_certificate(raw_cert)? else {
        return Ok(None);
    };
    let new_pkcs = strip_chain_then_unauth_pkcs7(pkcs_der)?;
    Ok(Some(repack_pkcs_signed_win_certificate(
        rev, typ, &new_pkcs,
    )))
}

fn read_certificate_blob(handle: HANDLE, index: u32) -> Result<Vec<u8>> {
    let mut hdr = WIN_CERTIFICATE::default();
    unsafe { ImageGetCertificateHeader(handle, index, &mut hdr)? };
    let len = hdr.dwLength as usize;
    if len < 8 {
        return Err(anyhow!("invalid certificate header length"));
    }
    let mut buf = vec![0u8; len];
    let mut req = len as u32;
    unsafe { ImageGetCertificateData(handle, index, buf.as_mut_ptr().cast(), &mut req)? };
    Ok(buf)
}

fn strip_pe_embedded_pkcs7(
    handle: HANDLE,
    rebuild: impl Fn(&[u8]) -> Result<Option<Vec<u8>>>,
) -> Result<()> {
    let mut count = 0u32;
    unsafe {
        ImageEnumerateCertificates(handle, CERT_SECTION_TYPE_ANY as u16, &mut count, None)?;
    }
    if count == 0 {
        return Err(anyhow!("no embedded certificates to process"));
    }

    let mut rebuilt: Vec<Vec<u8>> = Vec::with_capacity(count as usize);
    for idx in 0..count {
        let blob = read_certificate_blob(handle, idx)?;
        match rebuild(&blob)? {
            Some(v) => rebuilt.push(v),
            None => rebuilt.push(blob),
        };
    }

    for _ in 0..count {
        unsafe { ImageRemoveCertificate(handle, 0)? };
    }

    for cert_buf in rebuilt {
        let mut index = 0u32;
        unsafe {
            ImageAddCertificate(
                handle,
                cert_buf.as_ptr().cast::<WIN_CERTIFICATE>(),
                &mut index,
            )?;
        }
    }

    Ok(())
}

/// Apply native-style `remove /u` to an open PE file handle.
pub fn strip_unauthenticated_attributes_on_pe(handle: HANDLE) -> Result<()> {
    strip_pe_embedded_pkcs7(handle, rebuild_pkcs_win_certificate)
}

/// Apply native-style `remove /c` to an open PE file handle.
pub fn strip_chain_except_signer_on_pe(handle: HANDLE) -> Result<()> {
    strip_pe_embedded_pkcs7(handle, rebuild_pkcs_win_certificate_strip_chain)
}

/// Apply native-style `remove /c /u` on an open PE file handle (single PKCS#7 edit pass per blob).
pub fn strip_chain_and_unauthenticated_on_pe(handle: HANDLE) -> Result<()> {
    strip_pe_embedded_pkcs7(handle, rebuild_pkcs_win_certificate_strip_chain_and_unauth)
}

fn committed_changes_message(path: &Path, quiet: bool) -> String {
    if quiet {
        String::new()
    } else {
        format!(
            "Successfully committed changes to the file: {}\r\n\r\nNumber of errors: 0\r\n\r\n",
            path.display()
        )
    }
}

pub fn strip_unauthenticated_attributes_file(path: &Path, quiet: bool) -> Result<String> {
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
    let handle = HANDLE(file.as_raw_handle() as *mut _);

    strip_unauthenticated_attributes_on_pe(handle)
        .map_err(|e| anyhow!("remove /u failed for {}: {e}", path.display()))?;

    Ok(committed_changes_message(path, quiet))
}

pub fn strip_chain_except_signer_file(path: &Path, quiet: bool) -> Result<String> {
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
    let handle = HANDLE(file.as_raw_handle() as *mut _);

    strip_chain_except_signer_on_pe(handle)
        .map_err(|e| anyhow!("remove /c failed for {}: {e}", path.display()))?;

    Ok(committed_changes_message(path, quiet))
}

pub fn strip_chain_and_unauthenticated_file(path: &Path, quiet: bool) -> Result<String> {
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| anyhow!("failed to open {}: {e}", path.display()))?;
    let handle = HANDLE(file.as_raw_handle() as *mut _);

    strip_chain_and_unauthenticated_on_pe(handle)
        .map_err(|e| anyhow!("remove /c /u failed for {}: {e}", path.display()))?;

    Ok(committed_changes_message(path, quiet))
}
