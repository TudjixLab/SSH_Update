use crate::{Limits, Result, ensure};
pub const HEADER: usize = 160;
pub const DOMAIN: &[u8] = b"ULI4-SIGN-V1\0";
#[derive(Clone, Debug)]
pub struct Header {
    pub manifest_len: u64,
    pub index_len: u64,
    pub payload_len: u64,
    pub total_plain: u64,
    pub payload_hash: [u8; 32],
}
pub fn u64_at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
impl Header {
    pub fn index_offset(&self) -> u64 {
        160 + self.manifest_len
    }
    pub fn payload_offset(&self) -> u64 {
        self.index_offset() + self.index_len
    }
    pub fn signature_offset(&self) -> u64 {
        self.payload_offset() + self.payload_len
    }
    pub fn total(&self) -> u64 {
        self.signature_offset() + 96
    }
    pub fn encode(&self) -> [u8; HEADER] {
        let mut b = [0u8; HEADER];
        b[..4].copy_from_slice(b"ULI4");
        b[4..6].copy_from_slice(&1u16.to_le_bytes());
        b[8..12].copy_from_slice(&160u32.to_le_bytes());
        for (i, v) in [
            (16, 160),
            (24, self.manifest_len),
            (32, self.index_offset()),
            (40, self.index_len),
            (48, self.payload_offset()),
            (56, self.payload_len),
            (64, self.signature_offset()),
            (72, 96),
            (80, self.total()),
            (88, self.total_plain),
        ] {
            b[i..i + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[96..128].copy_from_slice(&self.payload_hash);
        b
    }
    pub fn decode(b: &[u8; HEADER], actual: u64, l: &Limits) -> Result<Self> {
        ensure(
            &b[..4] == b"ULI4"
                && b[4..8] == [1, 0, 0, 0]
                && b[8..16] == [160, 0, 0, 0, 0, 0, 0, 0]
                && b[128..].iter().all(|x| *x == 0),
            "ULI4_HEADER_INVALID",
        )?;
        let h = Self {
            manifest_len: u64_at(b, 24),
            index_len: u64_at(b, 40),
            payload_len: u64_at(b, 56),
            total_plain: u64_at(b, 88),
            payload_hash: b[96..128].try_into().unwrap(),
        };
        ensure(
            h.manifest_len <= l.manifest_bytes
                && h.index_len <= 8 + l.max_files.saturating_mul(64)
                && h.payload_len <= l.package_bytes
                && h.total_plain <= l.plain_bytes,
            "ULI4_QUOTA_EXCEEDED",
        )?;
        let total = [160, h.manifest_len, h.index_len, h.payload_len, 96]
            .into_iter()
            .try_fold(0u64, |n, v| n.checked_add(v))
            .ok_or(crate::Error::Rejected("ULI4_HEADER_INVALID"))?;
        ensure(
            total == actual
                && total <= l.package_bytes
                && u64_at(b, 16) == 160
                && u64_at(b, 32) == h.index_offset()
                && u64_at(b, 48) == h.payload_offset()
                && u64_at(b, 64) == h.signature_offset()
                && u64_at(b, 72) == 96
                && u64_at(b, 80) == total,
            "ULI4_HEADER_INVALID",
        )?;
        Ok(h)
    }
}
#[derive(Debug)]
pub struct Entry {
    pub operation: u32,
    pub offset: u64,
    pub compressed: u64,
    pub plain: u64,
    pub hash: [u8; 32],
}
pub fn encode_index(entries: &[Entry]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + 64 * entries.len());
    b.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for e in entries {
        b.extend_from_slice(&e.operation.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        for v in [e.offset, e.compressed, e.plain] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&e.hash);
    }
    b
}
pub fn decode_index(b: &[u8], l: &Limits) -> Result<Vec<Entry>> {
    ensure(b.len() >= 8, "ULI4_INDEX_INVALID")?;
    let n = u64_at(b, 0);
    ensure(
        n <= l.max_files
            && n.checked_mul(64).and_then(|x| x.checked_add(8)) == Some(b.len() as u64),
        "ULI4_INDEX_INVALID",
    )?;
    let mut result = Vec::new();
    for row in b[8..].as_chunks::<64>().0 {
        ensure(row[4..8] == [0; 4], "ULI4_INDEX_INVALID")?;
        result.push(Entry {
            operation: u32::from_le_bytes(row[..4].try_into().unwrap()),
            offset: u64_at(row, 8),
            compressed: u64_at(row, 16),
            plain: u64_at(row, 24),
            hash: row[32..].try_into().unwrap(),
        });
    }
    Ok(result)
}
pub fn signing_message(header: &[u8; HEADER], manifest: &[u8], index: &[u8]) -> Vec<u8> {
    [DOMAIN, header, manifest, index].concat()
}
