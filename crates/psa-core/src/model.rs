//! Order-4 character Markov model with Laplace smoothing.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;

use thiserror::Error;

pub const MODEL_MAGIC: &[u8; 4] = b"PSA4";
/// v1: transition entries are (u32 next_id, u32 count).
/// v2: pruned/quantized — (u16 next_id, u16 count) with counts saturated at u16::MAX.
pub const MODEL_VERSION: u32 = 2;
pub const MODEL_VERSION_V1: u32 = 1;
pub const ORDER: usize = 4;
pub const CONTEXT_LEN: usize = ORDER - 1; // 3

const BOS: &str = "\u{0001}"; // start-of-password padding char
const EOS: &str = "\u{0002}"; // end-of-password

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid model format: {0}")]
    Format(String),
}

/// Compact order-4 Markov over a learned character vocabulary.
#[derive(Debug, Clone)]
pub struct MarkovModel {
    /// Index 0 = BOS, last or dedicated = EOS; rest = training alphabet.
    pub vocab: Vec<String>,
    pub char_to_id: HashMap<char, u32>,
    /// context_key (packed 3 u16 ids) -> (next_id -> count)
    pub transitions: HashMap<u64, HashMap<u32, u32>>,
    pub laplace: f64,
    pub unk_id: u32,
    pub bos_id: u32,
    pub eos_id: u32,
}

fn pack_context(ids: &[u32; CONTEXT_LEN]) -> u64 {
    ((ids[0] as u64) << 32) | ((ids[1] as u64) << 16) | (ids[2] as u64)
}

impl MarkovModel {
    pub fn empty(laplace: f64) -> Self {
        let vocab = vec![BOS.to_string(), EOS.to_string(), "<unk>".to_string()];
        let mut char_to_id = HashMap::new();
        // BOS/EOS/unk are multi-byte conceptually; we map via sentinel chars
        char_to_id.insert('\u{0001}', 0);
        char_to_id.insert('\u{0002}', 1);
        Self {
            vocab,
            char_to_id,
            transitions: HashMap::new(),
            laplace,
            unk_id: 2,
            bos_id: 0,
            eos_id: 1,
        }
    }

    fn ensure_char(&mut self, c: char) -> u32 {
        if let Some(&id) = self.char_to_id.get(&c) {
            return id;
        }
        let id = self.vocab.len() as u32;
        self.vocab.push(c.to_string());
        self.char_to_id.insert(c, id);
        id
    }

    /// Train from an iterator of passwords (one string each).
    pub fn train_from_passwords<I, S>(passwords: I, laplace: f64) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut m = Self::empty(laplace);
        for pw in passwords {
            m.observe(pw.as_ref());
        }
        m
    }

    fn observe(&mut self, password: &str) {
        let mut ids: Vec<u32> = Vec::with_capacity(password.chars().count() + CONTEXT_LEN + 1);
        for _ in 0..CONTEXT_LEN {
            ids.push(self.bos_id);
        }
        for c in password.chars() {
            let id = self.ensure_char(c);
            ids.push(id);
        }
        ids.push(self.eos_id);

        for window in ids.windows(ORDER) {
            let ctx = [window[0], window[1], window[2]];
            let next = window[3];
            let key = pack_context(&ctx);
            *self
                .transitions
                .entry(key)
                .or_default()
                .entry(next)
                .or_insert(0) += 1;
        }
    }

    fn resolve_id(&self, c: char) -> u32 {
        self.char_to_id.get(&c).copied().unwrap_or(self.unk_id)
    }

    fn context_total_and_vocab(&self, key: u64) -> (f64, usize) {
        let v = self.vocab.len().max(1);
        let total = self
            .transitions
            .get(&key)
            .map(|m| m.values().map(|&c| c as f64).sum::<f64>())
            .unwrap_or(0.0);
        (total, v)
    }

    fn prob_next(&self, ctx: [u32; CONTEXT_LEN], next: u32) -> f64 {
        let key = pack_context(&ctx);
        let (total, v) = self.context_total_and_vocab(key);
        let count = self
            .transitions
            .get(&key)
            .and_then(|m| m.get(&next))
            .copied()
            .unwrap_or(0) as f64;
        (count + self.laplace) / (total + self.laplace * v as f64)
    }

    /// Probability of the full password under the model (includes EOS).
    pub fn probability(&self, password: &str) -> f64 {
        if password.is_empty() {
            // Only EOS after BOS context
            let ctx = [self.bos_id, self.bos_id, self.bos_id];
            return self.prob_next(ctx, self.eos_id);
        }

        let mut ctx = [self.bos_id, self.bos_id, self.bos_id];
        let mut p = 1.0_f64;
        for c in password.chars() {
            let id = self.resolve_id(c);
            p *= self.prob_next(ctx, id);
            ctx = [ctx[1], ctx[2], id];
        }
        p *= self.prob_next(ctx, self.eos_id);
        // Guard against underflow to exact 0 for ranking
        p.max(f64::MIN_POSITIVE)
    }

    /// Sample one password (for Monte Carlo training). `rng` yields u64.
    pub fn sample_password<R: FnMut() -> f64>(&self, max_len: usize, mut rng: R) -> String {
        let mut ctx = [self.bos_id, self.bos_id, self.bos_id];
        let mut out = String::new();
        for _ in 0..max_len {
            let next = self.sample_next(ctx, &mut rng);
            if next == self.eos_id {
                break;
            }
            if next == self.bos_id || next == self.unk_id {
                continue;
            }
            if let Some(s) = self.vocab.get(next as usize) {
                out.push_str(s);
            }
            ctx = [ctx[1], ctx[2], next];
        }
        out
    }

    fn sample_next<R: FnMut() -> f64>(&self, ctx: [u32; CONTEXT_LEN], rng: &mut R) -> u32 {
        let key = pack_context(&ctx);
        let (total, v) = self.context_total_and_vocab(key);
        let denom = total + self.laplace * v as f64;
        let mut r = rng() * denom;
        // Prefer iterating known transitions first, then uniform leftover over unseen
        if let Some(map) = self.transitions.get(&key) {
            for (&id, &count) in map {
                let mass = count as f64 + self.laplace;
                if r < mass {
                    return id;
                }
                r -= mass;
            }
            // Remaining mass for unseen ids
            for id in 0..self.vocab.len() as u32 {
                if map.contains_key(&id) {
                    continue;
                }
                let mass = self.laplace;
                if r < mass {
                    return id;
                }
                r -= mass;
            }
        } else {
            // Uniform over vocab with Laplace
            let id = (rng() * self.vocab.len() as f64).floor() as u32;
            return id.min(self.vocab.len() as u32 - 1);
        }
        self.eos_id
    }

    pub fn save_to_path(&self, path: impl AsRef<Path>) -> Result<(), ModelError> {
        let mut f = std::fs::File::create(path)?;
        self.write_to(&mut f)
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<(), ModelError> {
        if self.vocab.len() > u16::MAX as usize {
            return Err(ModelError::Format("vocab exceeds u16".into()));
        }
        w.write_all(MODEL_MAGIC)?;
        w.write_all(&MODEL_VERSION.to_le_bytes())?;
        w.write_all(&(ORDER as u32).to_le_bytes())?;
        w.write_all(&self.laplace.to_le_bytes())?;
        w.write_all(&self.bos_id.to_le_bytes())?;
        w.write_all(&self.eos_id.to_le_bytes())?;
        w.write_all(&self.unk_id.to_le_bytes())?;

        let n_vocab = self.vocab.len() as u32;
        w.write_all(&n_vocab.to_le_bytes())?;
        for s in &self.vocab {
            let bytes = s.as_bytes();
            let len = bytes.len() as u32;
            w.write_all(&len.to_le_bytes())?;
            w.write_all(bytes)?;
        }

        let n_ctx = self.transitions.len() as u32;
        w.write_all(&n_ctx.to_le_bytes())?;
        for (&key, map) in &self.transitions {
            w.write_all(&key.to_le_bytes())?;
            let n = map.len() as u32;
            w.write_all(&n.to_le_bytes())?;
            for (&id, &count) in map {
                let id16 = u16::try_from(id)
                    .map_err(|_| ModelError::Format(format!("next_id {id} exceeds u16")))?;
                let c16 = u16::try_from(count.min(u32::from(u16::MAX))).unwrap();
                w.write_all(&id16.to_le_bytes())?;
                w.write_all(&c16.to_le_bytes())?;
            }
        }
        Ok(())
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ModelError> {
        let mut f = std::fs::File::open(path)?;
        Self::read_from(&mut f)
    }

    pub fn load_from_bytes(data: &[u8]) -> Result<Self, ModelError> {
        let mut cursor = std::io::Cursor::new(data);
        Self::read_from(&mut cursor)
    }

    pub fn read_from<R: Read>(r: &mut R) -> Result<Self, ModelError> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != MODEL_MAGIC {
            return Err(ModelError::Format("bad magic".into()));
        }
        let version = read_u32(r)?;
        if version != MODEL_VERSION && version != MODEL_VERSION_V1 {
            return Err(ModelError::Format(format!("unsupported version {version}")));
        }
        let order = read_u32(r)? as usize;
        if order != ORDER {
            return Err(ModelError::Format(format!("unexpected order {order}")));
        }
        let laplace = read_f64(r)?;
        let bos_id = read_u32(r)?;
        let eos_id = read_u32(r)?;
        let unk_id = read_u32(r)?;

        let n_vocab = read_u32(r)? as usize;
        let mut vocab = Vec::with_capacity(n_vocab);
        let mut char_to_id = HashMap::new();
        for i in 0..n_vocab {
            let len = read_u32(r)? as usize;
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf)?;
            let s = String::from_utf8(buf).map_err(|e| ModelError::Format(e.to_string()))?;
            if s.chars().count() == 1 {
                if let Some(c) = s.chars().next() {
                    char_to_id.insert(c, i as u32);
                }
            } else if s == BOS {
                char_to_id.insert('\u{0001}', i as u32);
            } else if s == EOS {
                char_to_id.insert('\u{0002}', i as u32);
            }
            vocab.push(s);
        }

        let n_ctx = read_u32(r)? as usize;
        let mut transitions = HashMap::with_capacity(n_ctx);
        for _ in 0..n_ctx {
            let key = read_u64(r)?;
            let n = read_u32(r)? as usize;
            let mut map = HashMap::with_capacity(n);
            for _ in 0..n {
                let (id, count) = if version == MODEL_VERSION_V1 {
                    (read_u32(r)?, read_u32(r)?)
                } else {
                    let id = u32::from(read_u16(r)?);
                    let count = u32::from(read_u16(r)?);
                    (id, count)
                };
                map.insert(id, count);
            }
            transitions.insert(key, map);
        }

        Ok(Self {
            vocab,
            char_to_id,
            transitions,
            laplace,
            unk_id,
            bos_id,
            eos_id,
        })
    }
}

fn read_u16<R: Read>(r: &mut R) -> Result<u16, ModelError> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, ModelError> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64<R: Read>(r: &mut R) -> Result<u64, ModelError> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_f64<R: Read>(r: &mut R) -> Result<f64, ModelError> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(f64::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_prob() {
        let passwords = ["password", "password1", "admin", "welcome", "qwerty"];
        let m = MarkovModel::train_from_passwords(passwords, 0.01);
        let p = m.probability("password");
        assert!(p > 0.0 && p <= 1.0);
        let mut buf = Vec::new();
        m.write_to(&mut buf).unwrap();
        let m2 = MarkovModel::load_from_bytes(&buf).unwrap();
        let p2 = m2.probability("password");
        assert!((p - p2).abs() < 1e-12);
    }
}
