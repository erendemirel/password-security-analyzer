//! Shared result and option types for the advisory password analyzer.

use serde::{Deserialize, Serialize};

/// Strength label derived from guess-number / strength_bits (safe bias).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrengthLabel {
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

impl StrengthLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Fair => "fair",
            Self::Strong => "strong",
            Self::VeryStrong => "very_strong",
        }
    }

    pub fn from_str_label(s: &str) -> Option<Self> {
        match s {
            "weak" => Some(Self::Weak),
            "fair" => Some(Self::Fair),
            "strong" => Some(Self::Strong),
            "very_strong" => Some(Self::VeryStrong),
            _ => None,
        }
    }
}

/// Whether to query Have I Been Pwned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BreachPolicy {
    /// Skip the HIBP network call.
    Skip,
    /// Query HIBP (default).
    #[default]
    Check,
}

/// Options for [`crate::analyze`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeOptions {
    /// Identifies this client to HIBP (required by their API).
    pub user_agent: String,
    pub breach_policy: BreachPolicy,
    /// HTTP timeout in milliseconds for HIBP (native only; WASM uses browser defaults).
    pub timeout_ms: u64,
    /// When true, skip Markov/Monte Carlo (training-dependent) scoring.
    /// HIBP (if enabled) and `keyspace_bits` still run.
    pub skip_model: bool,
    /// Local Pwned Passwords store from
    /// [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)
    /// (directory of range files, or a single `HASH:COUNT` dump). When set with
    /// [`BreachPolicy::Check`], lookups use this path instead of the network API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hibp_offline_path: Option<String>,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            user_agent: "password-security-analyzer/0.1.0".to_string(),
            breach_policy: BreachPolicy::Check,
            timeout_ms: 5_000,
            skip_model: false,
            hibp_offline_path: None,
        }
    }
}

/// Breach check subset of the analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BreachResult {
    pub pwned: bool,
    pub occurrences: u64,
    pub source: String,
}

impl BreachResult {
    pub fn clean() -> Self {
        Self {
            pwned: false,
            occurrences: 0,
            source: "hibp_range".to_string(),
        }
    }

    pub fn clean_offline() -> Self {
        Self {
            pwned: false,
            occurrences: 0,
            source: "hibp_offline".to_string(),
        }
    }

    pub fn pwned(occurrences: u64) -> Self {
        Self {
            pwned: true,
            occurrences,
            source: "hibp_range".to_string(),
        }
    }

    pub fn pwned_offline(occurrences: u64) -> Self {
        Self {
            pwned: true,
            occurrences,
            source: "hibp_offline".to_string(),
        }
    }

    pub fn skipped() -> Self {
        Self {
            pwned: false,
            occurrences: 0,
            source: "skipped".to_string(),
        }
    }
}

/// Full advisory analysis result. Never treat as authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalyzeResult {
    /// Always true — this library does not enforce account creation.
    pub advisory: bool,
    /// True when HIBP matched and scoring was aborted early.
    pub aborted: bool,
    pub breach: BreachResult,
    /// Estimated attacker guesses under the Markov model (Monte Carlo). `None` if aborted/skipped.
    pub guess_number: Option<f64>,
    /// `log2(guess_number)` — primary strength metric. `None` if aborted/skipped.
    pub strength_bits: Option<f64>,
    /// Combinatorial keyspace size in bits: `log2(base^length)`.
    pub keyspace_bits: f64,
    pub label: Option<StrengthLabel>,
    pub reasons: Vec<String>,
}

impl AnalyzeResult {
    pub fn pwned_abort(breach: BreachResult, keyspace_bits: f64) -> Self {
        Self {
            advisory: true,
            aborted: true,
            breach,
            guess_number: None,
            strength_bits: None,
            keyspace_bits,
            label: Some(StrengthLabel::Weak),
            reasons: vec!["pwned_password".to_string()],
        }
    }
}
