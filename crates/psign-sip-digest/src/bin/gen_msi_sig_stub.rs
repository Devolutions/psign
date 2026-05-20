//! Build a minimal OLE compound file with root stream **`\u{5}DigitalSignature`** = first PE PKCS#7
//! from **`tiny32.signed.efi`** (for **`tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi`**).
//!
//! Not a real signed MSI ( **`verify-msi`** digest check fails** ); only PKCS#7 extract / RS256 prehash parity.
//!
//! ```text
//! cargo run -p psign-sip-digest --bin psign-gen-msi-signature-stub -- \
//!   tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi \
//!   tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi
//! ```

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use cfb::CompoundFile;
use psign_sip_digest::verify_pe;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let pe_path = args
        .next()
        .context("usage: psign-gen-msi-signature-stub <tiny32.signed.efi> <out.msi>")?;
    let out_path = args
        .next()
        .context("usage: psign-gen-msi-signature-stub <tiny32.signed.efi> <out.msi>")?;

    let pe = std::fs::read(&pe_path).with_context(|| format!("read {}", pe_path))?;
    let pkcs7 = verify_pe::pe_first_pkcs7_signed_data_der(&pe).context("PE PKCS#7")?;

    let f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&out_path)
        .with_context(|| format!("create {}", out_path))?;
    let mut cfb = CompoundFile::create(f).context("OLE create")?;
    let stream_path = Path::new("/").join("\u{5}DigitalSignature");
    let mut s = cfb
        .create_stream(&stream_path)
        .with_context(|| format!("create stream {:?}", stream_path))?;
    s.write_all(&pkcs7)
        .with_context(|| format!("write PKCS#7 ({} bytes)", pkcs7.len()))?;
    drop(s);
    drop(cfb);
    println!("Wrote {}", out_path);
    Ok(())
}
