//! Training-corpus membership index (data-driven, not a hand-curated phrase list).
//!
//! Passwords observed while training are hashed and ranked by frequency order.
//! Exact (or ASCII-lower) hits use that empirical rank as an upper bound on
//! guessability — the same role a leaked-password frequency table plays in
//! research meters, scaled to whatever wordlist you train on.

use std::io::{Read, Write};
use std::path::Path;

use thiserror::Error;

pub const KNOWN_MAGIC: &[u8; 4] = b"PSKN";
pub const KNOWN_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum KnownError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid known-password index: {0}")]
    Format(String),
}

/// Sorted (hash → rank) table. Rank 1 = most common in the training wordlist.
#[derive(Debug, Clone, Default)]
pub struct KnownPasswords {
    /// Parallel arrays sorted by `hashes` ascending for binary search.
    hashes: Vec<u64>,
    ranks: Vec<u32>,
}

impl KnownPasswords {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Build from passwords in descending-frequency order (first = rank 1).
    pub fn from_frequency_ordered<I, S>(passwords: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut pairs: Vec<(u64, u32)> = Vec::new();
        let mut seen_hash = std::collections::HashSet::new();
        let mut rank = 0u32;
        for pw in passwords {
            let s = pw.as_ref();
            if s.is_empty() {
                continue;
            }
            rank = rank.saturating_add(1);
            for key in hash_keys(s) {
                if seen_hash.insert(key) {
                    pairs.push((key, rank));
                }
            }
        }
        pairs.sort_by_key(|(h, _)| *h);
        // Keep lowest rank on accidental hash collisions after sort.
        pairs.dedup_by(|later, earlier| {
            if later.0 == earlier.0 {
                earlier.1 = earlier.1.min(later.1);
                true
            } else {
                false
            }
        });
        let hashes = pairs.iter().map(|(h, _)| *h).collect();
        let ranks = pairs.iter().map(|(_, r)| *r).collect();
        Self { hashes, ranks }
    }

    /// Empirical guess-rank if this password (or its ASCII-lower form) was trained.
    pub fn rank(&self, password: &str) -> Option<u32> {
        if self.hashes.is_empty() || password.is_empty() {
            return None;
        }
        let mut best: Option<u32> = None;
        for key in hash_keys(password) {
            if let Some(r) = self.lookup_hash(key) {
                best = Some(best.map_or(r, |b| b.min(r)));
            }
        }
        best
    }

    fn lookup_hash(&self, hash: u64) -> Option<u32> {
        self.hashes
            .binary_search(&hash)
            .ok()
            .map(|i| self.ranks[i])
    }

    pub fn save_to_path(&self, path: impl AsRef<Path>) -> Result<(), KnownError> {
        let mut f = std::fs::File::create(path)?;
        self.write_to(&mut f)
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<(), KnownError> {
        w.write_all(KNOWN_MAGIC)?;
        w.write_all(&KNOWN_VERSION.to_le_bytes())?;
        let n = self.hashes.len() as u32;
        w.write_all(&n.to_le_bytes())?;
        for (&h, &r) in self.hashes.iter().zip(self.ranks.iter()) {
            w.write_all(&h.to_le_bytes())?;
            w.write_all(&r.to_le_bytes())?;
        }
        Ok(())
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, KnownError> {
        let mut f = std::fs::File::open(path)?;
        Self::read_from(&mut f)
    }

    pub fn load_from_bytes(data: &[u8]) -> Result<Self, KnownError> {
        let mut c = std::io::Cursor::new(data);
        Self::read_from(&mut c)
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<Self, KnownError> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != KNOWN_MAGIC {
            return Err(KnownError::Format("bad magic".into()));
        }
        let mut ver = [0u8; 4];
        r.read_exact(&mut ver)?;
        if u32::from_le_bytes(ver) != KNOWN_VERSION {
            return Err(KnownError::Format("bad version".into()));
        }
        let mut nb = [0u8; 4];
        r.read_exact(&mut nb)?;
        let n = u32::from_le_bytes(nb) as usize;
        let mut hashes = Vec::with_capacity(n);
        let mut ranks = Vec::with_capacity(n);
        for _ in 0..n {
            let mut hb = [0u8; 8];
            let mut rb = [0u8; 4];
            r.read_exact(&mut hb)?;
            r.read_exact(&mut rb)?;
            hashes.push(u64::from_le_bytes(hb));
            ranks.push(u32::from_le_bytes(rb));
        }
        for w in hashes.windows(2) {
            if w[0] > w[1] {
                return Err(KnownError::Format("hashes not sorted".into()));
            }
        }
        Ok(Self { hashes, ranks })
    }
}

/// FNV-1a 64-bit — stable across Python trainer and Rust runtime, no extra deps.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn hash_keys(password: &str) -> Vec<u64> {
    let mut keys = vec![fnv1a64(password.as_bytes())];
    let lower = password.to_ascii_lowercase();
    if lower != password {
        keys.push(fnv1a64(lower.as_bytes()));
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_lookup_and_roundtrip() {
        let k = KnownPasswords::from_frequency_ordered(["password", "iloveyou", "ichliebedich"]);
        assert_eq!(k.rank("password"), Some(1));
        assert_eq!(k.rank("ILOVEYOU"), Some(2));
        assert_eq!(k.rank("ichliebedich"), Some(3));
        assert_eq!(k.rank("notintraining"), None);

        let mut buf = Vec::new();
        k.write_to(&mut buf).unwrap();
        let k2 = KnownPasswords::load_from_bytes(&buf).unwrap();
        assert_eq!(k2.rank("ichliebedich"), Some(3));
    }
}
