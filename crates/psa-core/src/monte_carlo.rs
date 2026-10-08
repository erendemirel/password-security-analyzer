//! Monte Carlo guess-number estimation (Dell'Amico & Filippone, CCS 2015).

use std::io::{Read, Write};
use std::path::Path;

use thiserror::Error;

use crate::model::MarkovModel;

pub const MC_MAGIC: &[u8; 4] = b"PSMC";
pub const MC_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum McError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid MC curve: {0}")]
    Format(String),
}

/// Precomputed curve: samples sorted by descending probability.
/// `neg_log2_p[i]` and corresponding cumulative rank `c[i]`.
#[derive(Debug, Clone)]
pub struct MonteCarloCurve {
    /// -log2(p) ascending (i.e. probability descending)
    pub neg_log2_p: Vec<f64>,
    /// Cumulative guess-rank estimates c_i
    pub ranks: Vec<f64>,
}

impl MonteCarloCurve {
    /// Build from a model by sampling until `target_unique` distinct probabilities.
    pub fn build_from_model(
        model: &MarkovModel,
        target_unique: usize,
        max_sample_attempts: usize,
        max_password_len: usize,
        mut rng: impl FnMut() -> f64,
    ) -> Self {
        // Map neg_log2_p -> weight sum for unique probs (keep max mass contribution)
        let mut unique: std::collections::BTreeMap<u64, f64> = std::collections::BTreeMap::new();
        // Use ordered by bit-pattern of f64 keys via ordered float as bits

        let mut attempts = 0usize;
        while unique.len() < target_unique && attempts < max_sample_attempts {
            attempts += 1;
            let pw = model.sample_password(max_password_len, &mut rng);
            let p = model.probability(&pw);
            let nlp = -p.log2();
            let key = nlp.to_bits();
            // For duplicate probs, keep one entry (unique probabilities)
            unique.entry(key).or_insert(p);
        }

        // Sort by descending probability => ascending neg_log2_p
        let mut items: Vec<(f64, f64)> = unique
            .into_iter()
            .map(|(bits, p)| (f64::from_bits(bits), p))
            .collect();
        items.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        let n = items.len() as f64;
        let mut neg_log2_p = Vec::with_capacity(items.len());
        let mut ranks = Vec::with_capacity(items.len());
        let mut cum = 0.0;
        for (nlp, p) in items {
            let p = p.max(f64::MIN_POSITIVE);
            cum += 1.0 / (n * p);
            neg_log2_p.push(nlp);
            ranks.push(cum);
        }

        Self { neg_log2_p, ranks }
    }

    /// Estimate guess number for a password probability.
    pub fn guess_number(&self, probability: f64) -> f64 {
        if self.neg_log2_p.is_empty() {
            return 1.0 / probability.max(f64::MIN_POSITIVE);
        }
        let nlp = -probability.max(f64::MIN_POSITIVE).log2();
        // Largest index j such that neg_log2_p[j] < nlp  (sample more probable than target)
        // Samples sorted ascending by neg_log2_p (more probable first).
        let j = match self
            .neg_log2_p
            .binary_search_by(|x| x.partial_cmp(&nlp).unwrap_or(std::cmp::Ordering::Equal))
        {
            Ok(i) => i.saturating_sub(1),
            Err(i) => i.saturating_sub(1),
        };
        if nlp <= self.neg_log2_p[0] {
            return self.ranks.first().copied().unwrap_or(1.0).max(1.0);
        }
        self.ranks
            .get(j)
            .copied()
            .unwrap_or_else(|| self.ranks.last().copied().unwrap_or(1.0 / probability))
            .max(1.0)
    }

    pub fn save_to_path(&self, path: impl AsRef<Path>) -> Result<(), McError> {
        let mut f = std::fs::File::create(path)?;
        self.write_to(&mut f)
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<(), McError> {
        w.write_all(MC_MAGIC)?;
        w.write_all(&MC_VERSION.to_le_bytes())?;
        let n = self.neg_log2_p.len() as u32;
        w.write_all(&n.to_le_bytes())?;
        for (&nlp, &rank) in self.neg_log2_p.iter().zip(self.ranks.iter()) {
            w.write_all(&nlp.to_le_bytes())?;
            w.write_all(&rank.to_le_bytes())?;
        }
        Ok(())
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, McError> {
        let mut f = std::fs::File::open(path)?;
        Self::read_from(&mut f)
    }

    pub fn load_from_bytes(data: &[u8]) -> Result<Self, McError> {
        let mut c = std::io::Cursor::new(data);
        Self::read_from(&mut c)
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<Self, McError> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != MC_MAGIC {
            return Err(McError::Format("bad magic".into()));
        }
        let mut ver = [0u8; 4];
        r.read_exact(&mut ver)?;
        if u32::from_le_bytes(ver) != MC_VERSION {
            return Err(McError::Format("bad version".into()));
        }
        let mut nb = [0u8; 4];
        r.read_exact(&mut nb)?;
        let n = u32::from_le_bytes(nb) as usize;
        let mut neg_log2_p = Vec::with_capacity(n);
        let mut ranks = Vec::with_capacity(n);
        for _ in 0..n {
            let mut a = [0u8; 8];
            let mut b = [0u8; 8];
            r.read_exact(&mut a)?;
            r.read_exact(&mut b)?;
            neg_log2_p.push(f64::from_le_bytes(a));
            ranks.push(f64::from_le_bytes(b));
        }
        Ok(Self { neg_log2_p, ranks })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::MarkovModel;

    #[test]
    fn curve_monotonic_guesses() {
        let pws = [
            "password",
            "password1",
            "password123",
            "admin",
            "admin1",
            "welcome",
            "qwerty",
            "letmein",
            "abc123",
            "monkey",
            "dragon",
            "master",
            "login",
            "princess",
            "solo",
        ];
        let m = MarkovModel::train_from_passwords(pws, 0.01);
        let mut s = 0x1234_5678_9abc_defu64;
        let mut rng = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s as f64) / (u64::MAX as f64)
        };
        let curve = MonteCarloCurve::build_from_model(&m, 200, 5000, 24, &mut rng);
        let g_common = curve.guess_number(m.probability("password"));
        let g_rare = curve.guess_number(m.probability("zzzxqqq99"));
        assert!(g_common >= 1.0);
        assert!(g_rare >= g_common * 0.5); // rare should not be wildly easier
        let mut buf = Vec::new();
        curve.write_to(&mut buf).unwrap();
        let c2 = MonteCarloCurve::load_from_bytes(&buf).unwrap();
        assert_eq!(c2.ranks.len(), curve.ranks.len());
    }
}
