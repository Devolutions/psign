//! Minimal ZIP writer for MSIX / AppX packages staged for portable signing.
//!
//! Windows AppxSip only accepts packages in the AppxPackaging (makeappx / signtool) ZIP
//! layout, and AppxPackaging expects deflated payloads to be split into independently
//! decodable 64 KiB blocks whose compressed sizes are listed in `AppxBlockMap.xml`.
//! Generic ZIP writers produce neither, so packages are written here: no data
//! descriptors or extra fields, "version made by" 45, zero external attributes, and
//! ZIP64 end records (via [`msix_digest::normalize_zip_for_appx_signing`]).

use anyhow::{Result, bail};
use flate2::{Compress, Compression, FlushCompress, Status};
use psign_sip_digest::msix_digest;

/// AppxBlockMap block size (uncompressed bytes per `Block`).
pub(crate) const APPX_BLOCK_SIZE: usize = 64 * 1024;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATED: u16 = 8;
const LOCAL_HEADER_SIG: u32 = 0x0403_4b50;
const CENTRAL_HEADER_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
/// MS-DOS date for 1980-01-01 (time 00:00:00), matching the `zip` crate default.
const DOS_DATE_1980: u16 = 0x21;

/// Extensions makeappx stores without compression because they are already compressed.
const STORED_EXTENSIONS: &[&str] = &[
    "png",
    "jpg",
    "jpeg",
    "gif",
    "zip",
    "gz",
    "7z",
    "cab",
    "appx",
    "msix",
    "appxbundle",
    "msixbundle",
    "eappx",
    "emsix",
    "mp3",
    "mp4",
    "wma",
    "wmv",
    "m4a",
];

pub(crate) struct AppxZipEntry {
    pub(crate) name: String,
    method: u16,
    crc32: u32,
    uncompressed_size: u64,
    data: Vec<u8>,
    /// Compressed size of each 64 KiB block of a deflated entry (`Block/@Size`).
    pub(crate) block_sizes: Option<Vec<u64>>,
}

impl AppxZipEntry {
    /// An uncompressed entry.
    pub(crate) fn stored(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            method: METHOD_STORED,
            crc32: crc32(&data),
            uncompressed_size: data.len() as u64,
            data,
            block_sizes: None,
        }
    }

    /// A payload entry, deflated in AppX blocks unless that does not make it smaller.
    pub(crate) fn payload(name: impl Into<String>, data: &[u8]) -> Result<Self> {
        let name = name.into();
        let extension = name
            .rsplit('/')
            .next()
            .and_then(|leaf| leaf.rsplit_once('.'))
            .map(|(_, ext)| ext.to_ascii_lowercase())
            .unwrap_or_default();
        if data.is_empty() || STORED_EXTENSIONS.contains(&extension.as_str()) {
            return Ok(Self::stored(name, data.to_vec()));
        }
        let (compressed, block_sizes) = deflate_appx_blocks(data)?;
        if compressed.len() >= data.len() {
            return Ok(Self::stored(name, data.to_vec()));
        }
        Ok(Self {
            name,
            method: METHOD_DEFLATED,
            crc32: crc32(data),
            uncompressed_size: data.len() as u64,
            data: compressed,
            block_sizes: Some(block_sizes),
        })
    }

    /// An entry copied byte-for-byte (already compressed with `method`) from a staged package.
    pub(crate) fn raw(
        name: impl Into<String>,
        method: u16,
        crc32: u32,
        uncompressed_size: u64,
        data: Vec<u8>,
    ) -> Result<Self> {
        if !matches!(method, METHOD_STORED | METHOD_DEFLATED) {
            bail!("unsupported ZIP compression method {method} in staged MSIX package");
        }
        Ok(Self {
            name: name.into(),
            method,
            crc32,
            uncompressed_size,
            data,
            block_sizes: None,
        })
    }

    /// Local file header size, as listed in `File/@LfhSize`.
    pub(crate) fn local_header_size(&self) -> usize {
        30 + self.name.len()
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

/// Raw-deflate `data` as AppxPackaging does: every 64 KiB block ends with a full flush, so
/// each block's compressed bytes decode on their own, followed by an empty final block.
/// Returns the compressed stream and each block's compressed size.
pub(crate) fn deflate_appx_blocks(data: &[u8]) -> Result<(Vec<u8>, Vec<u64>)> {
    let mut compress = Compress::new(Compression::default(), false);
    let mut out = Vec::with_capacity(data.len() / 2 + 64);
    let mut block_sizes = Vec::with_capacity(data.len().div_ceil(APPX_BLOCK_SIZE));
    for block in data.chunks(APPX_BLOCK_SIZE) {
        let start = out.len();
        deflate_into(&mut compress, block, FlushCompress::Full, &mut out)?;
        block_sizes.push((out.len() - start) as u64);
    }
    deflate_into(&mut compress, &[], FlushCompress::Finish, &mut out)?;
    Ok((out, block_sizes))
}

fn deflate_into(
    compress: &mut Compress,
    mut input: &[u8],
    flush: FlushCompress,
    out: &mut Vec<u8>,
) -> Result<()> {
    loop {
        out.reserve(input.len() + 1024);
        let before = compress.total_in();
        let status = compress.compress_vec(input, out, flush)?;
        let consumed = usize::try_from(compress.total_in() - before)?;
        input = &input[consumed..];
        // A flush is complete once the encoder stops filling the spare output capacity.
        if status == Status::StreamEnd
            || (!matches!(flush, FlushCompress::Finish)
                && input.is_empty()
                && out.len() < out.capacity())
        {
            return Ok(());
        }
    }
}

fn u32_field(value: u64, what: &str) -> Result<u32> {
    u32::try_from(value)
        .ok()
        .filter(|&v| v != u32::MAX)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{what} exceeds 4 GiB; portable MSIX signing does not write ZIP64 entries"
            )
        })
}

/// Serialize `entries` in order into an AppxPackaging-layout ZIP.
pub(crate) fn write_appx_zip(entries: &[AppxZipEntry]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for entry in entries {
        let name = entry.name.as_bytes();
        let name_len = u16::try_from(name.len())?;
        // Bit 11: entry name is UTF-8.
        let flags: u16 = if entry.name.is_ascii() { 0 } else { 1 << 11 };
        let offset = u32_field(out.len() as u64, "MSIX package size")?;
        let compressed_size = u32_field(entry.data.len() as u64, "MSIX entry size")?;
        let uncompressed_size = u32_field(entry.uncompressed_size, "MSIX entry size")?;

        out.extend_from_slice(&LOCAL_HEADER_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&entry.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&DOS_DATE_1980.to_le_bytes());
        out.extend_from_slice(&entry.crc32.to_le_bytes());
        out.extend_from_slice(&compressed_size.to_le_bytes());
        out.extend_from_slice(&uncompressed_size.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&entry.data);

        central.extend_from_slice(&CENTRAL_HEADER_SIG.to_le_bytes());
        central.extend_from_slice(&45u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&entry.method.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&DOS_DATE_1980.to_le_bytes());
        central.extend_from_slice(&entry.crc32.to_le_bytes());
        central.extend_from_slice(&compressed_size.to_le_bytes());
        central.extend_from_slice(&uncompressed_size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        // Extra length, comment length, disk number start, internal attributes.
        central.extend_from_slice(&[0; 8]);
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let entry_count = u16::try_from(entries.len())
        .ok()
        .filter(|&n| n != u16::MAX)
        .ok_or_else(|| anyhow::anyhow!("too many MSIX package entries"))?;
    let cd_offset = u32_field(out.len() as u64, "MSIX package size")?;
    let cd_size = u32_field(central.len() as u64, "MSIX central directory size")?;
    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    msix_digest::normalize_zip_for_appx_signing(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Decompress, FlushDecompress};

    fn inflate_raw(data: &[u8], expected_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(expected_len + 16);
        Decompress::new(false)
            .decompress_vec(data, &mut out, FlushDecompress::Sync)
            .expect("inflate");
        out
    }

    #[test]
    fn deflated_blocks_decode_independently() {
        let data: Vec<u8> = (0..200_000u32)
            .flat_map(|i| format!("row-{}|", i % 5000).into_bytes())
            .collect();
        let (compressed, sizes) = deflate_appx_blocks(&data).unwrap();
        assert_eq!(sizes.len(), data.len().div_ceil(APPX_BLOCK_SIZE));
        assert!(compressed.len() < data.len() / 2);

        let mut offset = 0usize;
        for (block, size) in data.chunks(APPX_BLOCK_SIZE).zip(&sizes) {
            let size = usize::try_from(*size).unwrap();
            let decoded = inflate_raw(&compressed[offset..offset + size], block.len());
            assert_eq!(
                decoded, block,
                "each block must decode without prior blocks"
            );
            offset += size;
        }
        // Only the empty final block follows the last flushed block.
        assert!(compressed.len() - offset <= 8);

        let mut whole = Vec::with_capacity(data.len() + 16);
        Decompress::new(false)
            .decompress_vec(&compressed, &mut whole, FlushDecompress::Finish)
            .unwrap();
        assert_eq!(whole, data);
    }

    #[test]
    fn payload_stores_precompressed_and_incompressible_data() {
        assert!(
            AppxZipEntry::payload("Assets/logo.png", &[7; 4096])
                .unwrap()
                .block_sizes
                .is_none()
        );
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let noise: Vec<u8> = (0..70_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect();
        let entry = AppxZipEntry::payload("noise.bin", &noise).unwrap();
        assert_eq!(entry.method, METHOD_STORED);
        let text = AppxZipEntry::payload("index.db", &[b'a'; 70_000]).unwrap();
        assert_eq!(text.method, METHOD_DEFLATED);
        assert_eq!(text.block_sizes.as_ref().map(Vec::len), Some(2));
    }

    #[test]
    fn written_zip_round_trips_through_zip_reader() {
        let entries = vec![
            AppxZipEntry::payload("AppxManifest.xml", &[b'x'; 100_000]).unwrap(),
            AppxZipEntry::stored("Public/empty.db", Vec::new()),
            AppxZipEntry::stored("AppxSignature.p7x", b"PKCX".to_vec()),
        ];
        let zip = write_appx_zip(&entries).unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&zip)).unwrap();
        assert_eq!(archive.len(), 3);
        let mut manifest = Vec::new();
        std::io::Read::read_to_end(&mut archive.by_index(0).unwrap(), &mut manifest).unwrap();
        assert_eq!(manifest, vec![b'x'; 100_000]);
        let first = archive.by_index(0).unwrap();
        assert_eq!(
            first.data_start() - first.header_start(),
            entries[0].local_header_size() as u64
        );
    }
}
