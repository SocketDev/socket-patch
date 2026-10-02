//! Deterministic building blocks for synthetic projects: a seeded RNG,
//! package names and versions, and well-formed (fake) digests. The same
//! seed always yields byte-identical fixtures, so base and head scan the
//! same bytes and a run is reproducible from its scenario name.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha2::Digest as _;

/// splitmix64: tiny, fast, and good enough for picking names.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: &str) -> Self {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in seed.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        Self(h)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        ((self.next_u64() >> 11) as f64 / (1u64 << 53) as f64) < p
    }
}

const SYLLABLES: &[&str] = &[
    "ab", "ac", "al", "an", "ar", "as", "at", "ba", "be", "bi", "bo", "ca", "ce", "ch", "co", "da",
    "de", "di", "do", "el", "en", "er", "es", "fa", "fe", "fi", "fo", "ga", "ge", "go", "ha", "he",
    "hi", "in", "is", "ja", "jo", "ka", "ki", "la", "le", "li", "lo", "ma", "me", "mi", "mo", "na",
    "ne", "ni", "no", "on", "or", "pa", "pe", "pi", "po", "qu", "ra", "re", "ri", "ro", "sa", "se",
    "si", "so", "ta", "te", "ti", "to", "un", "ur", "va", "ve", "vi", "wa", "we", "xe", "ya", "zo",
];

/// A unique lowercase identifier: two to four syllables plus the index,
/// so names have realistic, varied lengths and never collide.
pub fn ident(rng: &mut Rng, index: usize) -> String {
    let n = 2 + rng.below(3);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(SYLLABLES[rng.below(SYLLABLES.len())]);
    }
    format!("{s}{index}")
}

/// A plausible semver version.
pub fn version(rng: &mut Rng) -> String {
    let major = match rng.below(10) {
        0..=5 => rng.below(4),
        6..=8 => 4 + rng.below(8),
        _ => 12 + rng.below(20),
    };
    format!("{major}.{}.{}", rng.below(25), rng.below(15))
}

pub fn sha512_bytes(seed: &str) -> [u8; 64] {
    sha2::Sha512::digest(seed.as_bytes()).into()
}

/// An npm-style SRI string, `sha512-<base64>`.
pub fn sri_sha512(seed: &str) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha512_bytes(seed))
    )
}

pub fn sha512_hex(seed: &str) -> String {
    hex::encode(sha512_bytes(seed))
}

pub fn sha256_hex(seed: &str) -> String {
    hex::encode(sha2::Sha256::digest(seed.as_bytes()))
}

pub fn sha1_hex(seed: &str) -> String {
    hex::encode(sha1::Sha1::digest(seed.as_bytes()))
}

pub fn sha256_base64(seed: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(seed.as_bytes()))
}

/// A deterministic v4-shaped UUID.
pub fn uuid(seed: &str) -> String {
    let h = sha2::Sha256::digest(seed.as_bytes());
    let x = hex::encode(&h[..16]);
    format!(
        "{}-{}-4{}-8{}-{}",
        &x[0..8],
        &x[8..12],
        &x[13..16],
        &x[17..20],
        &x[20..32]
    )
}

/// Writes files under a root, creating parents as needed.
pub struct Tree {
    root: PathBuf,
}

impl Tree {
    pub fn new(root: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    pub fn write(&mut self, rel: &str, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(p, contents)
    }

    pub fn mkdir(&mut self, rel: &str) -> std::io::Result<()> {
        std::fs::create_dir_all(self.root.join(rel))
    }

    pub fn symlink(&mut self, target: &str, rel: &str) -> std::io::Result<()> {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::tree::symlink(Path::new(target), &p)
    }
}

/// A small but non-trivial JS source file, so installed packages carry
/// some bytes the way real ones do (the crawl never reads them, but the
/// directory walk and any hashing would).
pub fn js_source(name: &str, rng: &mut Rng) -> String {
    let fns = 2 + rng.below(6);
    let mut s = format!("'use strict';\n// {name}\n");
    for i in 0..fns {
        s.push_str(&format!(
            "function f{i}(a, b) {{\n  return (a ?? {i}) + (b ?? {}) * {};\n}}\nexports.f{i} = f{i};\n",
            rng.below(100),
            rng.below(1000)
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic_per_seed() {
        let a: Vec<u64> = (0..4)
            .map({
                let mut r = Rng::new("npm");
                move |_| r.next_u64()
            })
            .collect();
        let b: Vec<u64> = (0..4)
            .map({
                let mut r = Rng::new("npm");
                move |_| r.next_u64()
            })
            .collect();
        let c = Rng::new("pnpm").next_u64();
        assert_eq!(a, b);
        assert_ne!(a[0], c);
    }

    #[test]
    fn idents_are_unique_and_lowercase() {
        let mut rng = Rng::new("x");
        let names: std::collections::HashSet<String> =
            (0..5000).map(|i| ident(&mut rng, i)).collect();
        assert_eq!(names.len(), 5000);
        assert!(names.iter().all(|n| n
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())));
    }

    #[test]
    fn digests_are_well_formed() {
        assert!(sri_sha512("a").starts_with("sha512-"));
        assert_eq!(sri_sha512("a").len(), 7 + 88);
        assert_eq!(sha256_hex("a").len(), 64);
        assert_eq!(sha1_hex("a").len(), 40);
        let u = uuid("a");
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert_eq!(&u[19..20], "8");
    }
}
