//! Identity facts for downloaded npm archives.

pub struct PackedTarball {
    pub yarn_berry10c0: Option<String>,
    /// SRI string: `"sha512-" + base64(sha512(tgz bytes))`.
    pub integrity: String,
    /// Plain sha256 hex of the tgz bytes (the vendor ledger's artifact hash).
    pub sha256_hex: String,
    /// Plain sha1 hex of the tgz bytes (the checksum field yarn-classic and
    /// other legacy lockfile flavors record for tarballs).
    pub sha1_hex: String,
    /// Byte size of the tgz.
    pub size: u64,
}

impl PackedTarball {
    /// Compute the tarball's identity facts (sha512 SRI / sha256 / sha1 / size)
    /// from its bytes, writing nothing.
    ///
    pub fn from_bytes(bytes: &[u8]) -> PackedTarball {
        PackedTarball {
            yarn_berry10c0: None,
            integrity: crate::utils::digest::sha512_sri_of(bytes),
            sha256_hex: crate::utils::digest::sha256_hex_of(bytes),
            sha1_hex: crate::utils::digest::sha1_hex_of(bytes),
            size: bytes.len() as u64,
        }
    }
}
