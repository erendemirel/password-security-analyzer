//! Have I Been Pwned Pwned Passwords — online range API + offline store.
//!
//! Offline layout matches [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader):
//! a directory of per-prefix range files (`{PREFIX}` or `{PREFIX}.txt`) whose lines are
//! `SUFFIX:COUNT` (same as the k-anonymity API body).

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};
use thiserror::Error;

use crate::types::BreachResult;

pub const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

#[derive(Debug, Error)]
pub enum HibpError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("invalid HIBP response")]
    InvalidResponse,
    #[error("offline HIBP store error: {0}")]
    Offline(String),
}

/// Minimal HTTP GET used by HIBP so native and WASM can plug different stacks.
pub trait HttpGet {
    fn get_text(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<String, HibpError>;
}

/// SHA-1 hex (uppercase) of UTF-8 password bytes.
pub fn sha1_hex_upper(password: &str) -> String {
    let digest = Sha1::digest(password.as_bytes());
    hex::encode_upper(digest)
}

/// Split into 5-char prefix and 35-char suffix (uppercase hex).
pub fn hash_prefix_suffix(password: &str) -> (String, String) {
    let full = sha1_hex_upper(password);
    let (prefix, suffix) = full.split_at(5);
    (prefix.to_string(), suffix.to_string())
}

/// Parse HIBP range body; ignore padding lines with count 0.
/// Returns occurrences if `suffix` (uppercase) is present.
pub fn match_range_body(body: &str, suffix_upper: &str) -> Result<Option<u64>, HibpError> {
    let target = suffix_upper.to_ascii_uppercase();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (suf, count_str) = line.split_once(':').ok_or(HibpError::InvalidResponse)?;
        let count: u64 = count_str
            .trim()
            .parse()
            .map_err(|_| HibpError::InvalidResponse)?;
        if count == 0 {
            // Padding entry
            continue;
        }
        if suf.trim().eq_ignore_ascii_case(&target) {
            return Ok(Some(count));
        }
    }
    Ok(None)
}

/// Query HIBP range API via the provided HTTP client.
pub fn check_pwned<H: HttpGet>(
    password: &str,
    user_agent: &str,
    http: &H,
) -> Result<BreachResult, HibpError> {
    let (prefix, suffix) = hash_prefix_suffix(password);
    let url = format!("{HIBP_RANGE_URL}{prefix}");
    let headers = [
        ("User-Agent", user_agent),
        ("Add-Padding", "true"),
    ];
    let body = http.get_text(&url, &headers)?;
    match match_range_body(&body, &suffix)? {
        Some(n) => Ok(BreachResult::pwned(n)),
        None => Ok(BreachResult::clean()),
    }
}

/// Offline store produced by `haveibeenpwned-downloader` (directory of range files)
/// or a single-file dump (`FULLHASH:COUNT` lines).
#[derive(Debug, Clone)]
pub struct OfflineHibpStore {
    path: PathBuf,
}

impl OfflineHibpStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, HibpError> {
        let path = path.into();
        if !path.exists() {
            return Err(HibpError::Offline(format!(
                "path does not exist: {}",
                path.display()
            )));
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn check(&self, password: &str) -> Result<BreachResult, HibpError> {
        check_pwned_offline(password, &self.path)
    }
}

/// Look up a password in a PwnedPasswordsDownloader-compatible path.
pub fn check_pwned_offline(password: &str, store_path: &Path) -> Result<BreachResult, HibpError> {
    let (prefix, suffix) = hash_prefix_suffix(password);
    let full = format!("{prefix}{suffix}");

    if store_path.is_dir() {
        return check_offline_dir(store_path, &prefix, &suffix);
    }
    if store_path.is_file() {
        return check_offline_file(store_path, &prefix, &suffix, &full);
    }
    Err(HibpError::Offline(format!(
        "not a file or directory: {}",
        store_path.display()
    )))
}

fn check_offline_dir(
    dir: &Path,
    prefix: &str,
    suffix: &str,
) -> Result<BreachResult, HibpError> {
    let candidates = [
        dir.join(prefix),
        dir.join(format!("{prefix}.txt")),
        dir.join(prefix.to_ascii_lowercase()),
        dir.join(format!("{}.txt", prefix.to_ascii_lowercase())),
    ];
    for path in &candidates {
        if path.is_file() {
            let body = fs::read_to_string(path).map_err(|e| {
                HibpError::Offline(format!("read {}: {e}", path.display()))
            })?;
            return match match_range_body(&body, suffix)? {
                Some(n) => Ok(BreachResult::pwned_offline(n)),
                None => Ok(BreachResult::clean_offline()),
            };
        }
    }
    // Incomplete subset (e2e): missing prefix ⇒ treat as not present in local store.
    Ok(BreachResult::clean_offline())
}

fn check_offline_file(
    path: &Path,
    prefix: &str,
    suffix: &str,
    full_hash: &str,
) -> Result<BreachResult, HibpError> {
    let file_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_uppercase();
    // Range file named after its prefix (API body format).
    if file_stem == prefix {
        let body = fs::read_to_string(path)
            .map_err(|e| HibpError::Offline(format!("read {}: {e}", path.display())))?;
        return match match_range_body(&body, suffix)? {
            Some(n) => Ok(BreachResult::pwned_offline(n)),
            None => Ok(BreachResult::clean_offline()),
        };
    }

    // Single-file dump from `haveibeenpwned-downloader --single`: FULLHASH:COUNT
    let f = fs::File::open(path)
        .map_err(|e| HibpError::Offline(format!("open {}: {e}", path.display())))?;
    let reader = BufReader::new(f);
    let target = full_hash.to_ascii_uppercase();
    for line in reader.lines() {
        let line = line.map_err(|e| HibpError::Offline(e.to_string()))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (hash, count_str) = line.split_once(':').ok_or(HibpError::InvalidResponse)?;
        let hash = hash.trim();
        if hash.len() == 40 && hash.eq_ignore_ascii_case(&target) {
            let count: u64 = count_str
                .trim()
                .parse()
                .map_err(|_| HibpError::InvalidResponse)?;
            if count == 0 {
                return Ok(BreachResult::clean_offline());
            }
            return Ok(BreachResult::pwned_offline(count));
        }
        // Also accept suffix-only lines if the whole file is one range body.
        if hash.len() == 35 && hash.eq_ignore_ascii_case(suffix) {
            let count: u64 = count_str
                .trim()
                .parse()
                .map_err(|_| HibpError::InvalidResponse)?;
            if count == 0 {
                continue;
            }
            return Ok(BreachResult::pwned_offline(count));
        }
    }
    Ok(BreachResult::clean_offline())
}

/// Blocking reqwest implementation (native).
#[cfg(feature = "native-http")]
pub struct NativeHttp {
    pub timeout_ms: u64,
}

#[cfg(feature = "native-http")]
impl Default for NativeHttp {
    fn default() -> Self {
        Self { timeout_ms: 5_000 }
    }
}

#[cfg(feature = "native-http")]
impl HttpGet for NativeHttp {
    fn get_text(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<String, HibpError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .build()
            .map_err(|e| HibpError::Http(e.to_string()))?;
        let mut req = client.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = req.send().map_err(|e| HibpError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(HibpError::Http(format!("status {}", resp.status())));
        }
        resp.text().map_err(|e| HibpError::Http(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn known_sha1_password() {
        // SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (p, s) = hash_prefix_suffix("password");
        assert_eq!(p, "5BAA6");
        assert_eq!(s, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn parse_range_with_padding() {
        let body = "\
1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\n\
AAAA0000000000000000000000000000000:0\n\
BBBB1111111111111111111111111111111:2\n";
        let n = match_range_body(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
            .unwrap()
            .unwrap();
        assert_eq!(n, 3861493);
        assert!(match_range_body(body, "AAAA0000000000000000000000000000000")
            .unwrap()
            .is_none());
        assert_eq!(
            match_range_body(body, "bbbb1111111111111111111111111111111")
                .unwrap()
                .unwrap(),
            2
        );
    }

    struct MockHttp(String);
    impl HttpGet for MockHttp {
        fn get_text(&self, _url: &str, _headers: &[(&str, &str)]) -> Result<String, HibpError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn check_pwned_mock_hit() {
        let suffix = hash_prefix_suffix("password").1;
        let body = format!("{suffix}:99\nDEAD:0\n");
        let r = check_pwned("password", "test-agent", &MockHttp(body)).unwrap();
        assert!(r.pwned);
        assert_eq!(r.occurrences, 99);
    }

    #[test]
    fn offline_dir_range_hit() {
        let dir = std::env::temp_dir().join(format!(
            "psa_hibp_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (prefix, suffix) = hash_prefix_suffix("password");
        let mut f = fs::File::create(dir.join(format!("{prefix}.txt"))).unwrap();
        writeln!(f, "{suffix}:42").unwrap();
        writeln!(f, "DEADBEEF000000000000000000000000000:0").unwrap();

        let r = check_pwned_offline("password", &dir).unwrap();
        assert!(r.pwned);
        assert_eq!(r.occurrences, 42);
        assert_eq!(r.source, "hibp_offline");

        let miss = check_pwned_offline("not_in_this_tiny_store_xyz", &dir).unwrap();
        assert!(!miss.pwned);
        assert_eq!(miss.source, "hibp_offline");

        let _ = fs::remove_dir_all(&dir);
    }
}
