//! Top-level analyze / check_pwned entry points.

use std::path::Path;
use std::sync::OnceLock;

use crate::keyspace::keyspace_bits;
use crate::hibp::{self, HibpError, HttpGet};
use crate::known::{KnownError, KnownPasswords};
use crate::model::{MarkovModel, ModelError};
use crate::monte_carlo::{McError, MonteCarloCurve};
use crate::score::{label_from_guess_number, strength_bits};
use crate::sequences::apply_sequence_demotion;
use crate::structure::apply_structure_demotion;
use crate::types::{AnalyzeOptions, AnalyzeResult, BreachPolicy, BreachResult, StrengthLabel};

#[derive(Debug, thiserror::Error)]
pub enum AnalyzeError {
    #[error(transparent)]
    Hibp(#[from] HibpError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Mc(#[from] McError),
    #[error(transparent)]
    Known(#[from] KnownError),
    #[error("model not available: {0}")]
    NoModel(String),
}

/// Bundled default model (only with `embedded-model` feature).
#[cfg(feature = "embedded-model")]
static DEFAULT_ENGINE: OnceLock<Result<ScoringEngine, String>> = OnceLock::new();

/// Markov + Monte Carlo + training-corpus index (training-dependent).
#[derive(Debug, Clone)]
pub struct ScoringEngine {
    pub model: MarkovModel,
    pub curve: MonteCarloCurve,
    pub known: KnownPasswords,
}

impl ScoringEngine {
    pub fn from_paths(
        model_path: impl AsRef<Path>,
        curve_path: impl AsRef<Path>,
        known_path: Option<&Path>,
    ) -> Result<Self, AnalyzeError> {
        let known = match known_path {
            Some(p) => KnownPasswords::load_from_path(p)?,
            None => KnownPasswords::empty(),
        };
        Ok(Self {
            model: MarkovModel::load_from_path(model_path)?,
            curve: MonteCarloCurve::load_from_path(curve_path)?,
            known,
        })
    }

    pub fn from_bytes(
        model: &[u8],
        curve: &[u8],
        known: Option<&[u8]>,
    ) -> Result<Self, AnalyzeError> {
        Ok(Self {
            model: MarkovModel::load_from_bytes(model)?,
            curve: MonteCarloCurve::load_from_bytes(curve)?,
            known: match known {
                Some(b) => KnownPasswords::load_from_bytes(b)?,
                None => KnownPasswords::empty(),
            },
        })
    }

    pub fn score_password(&self, password: &str) -> (f64, f64, StrengthLabel, Vec<String>) {
        let p = self.model.probability(password);
        let mut guesses = self.curve.guess_number(p);
        let mut reasons: Vec<String> = Vec::new();

        // Data-driven: passwords seen in the training wordlist use empirical rank.
        if let Some(rank) = self.known.rank(password) {
            let known_guesses = f64::from(rank);
            if known_guesses < guesses {
                guesses = known_guesses;
                reasons.push("known_from_training".to_string());
            }
        }

        // Markov can overrate short "random-looking" strings (low model probability →
        // huge guess numbers). An attacker can always brute-force the observed
        // character classes, so never claim more guesses than 2^keyspace_bits.
        // Applied silently (not a user-facing "reason" like sequential_run).
        let ks = keyspace_bits(password);
        if ks.is_finite() && ks >= 0.0 {
            let keyspace_guesses = 2f64.powf(ks);
            if keyspace_guesses.is_finite() && keyspace_guesses < guesses {
                guesses = keyspace_guesses;
            }
        }

        let bits = strength_bits(guesses);
        let mut label = label_from_guess_number(guesses);

        // Structural demotion for Markov blind spots (sequences, tiles, constants).
        let (label2, seq) = apply_sequence_demotion(label, password);
        label = label2;
        reasons.extend(seq.into_iter().map(str::to_string));

        let (label3, st) = apply_structure_demotion(label, password);
        label = label3;
        reasons.extend(st.into_iter().map(str::to_string));

        (guesses, bits, label, reasons)
    }
}

/// `true` when this build embeds the default Markov/MC artifacts.
pub const fn has_embedded_model() -> bool {
    cfg!(feature = "embedded-model")
}

fn model_skipped_result(breach: BreachResult, keyspace_bits: f64, reason: &str) -> AnalyzeResult {
    AnalyzeResult {
        advisory: true,
        aborted: false,
        breach,
        guess_number: None,
        strength_bits: None,
        keyspace_bits,
        label: None,
        reasons: vec![reason.to_string()],
    }
}

#[cfg(feature = "embedded-model")]
fn embedded_engine() -> Result<&'static ScoringEngine, AnalyzeError> {
    let res = DEFAULT_ENGINE.get_or_init(|| {
        let model = include_bytes!("../../../models/markov4.bin");
        let curve = include_bytes!("../../../models/mc_curve.bin");
        let known = include_bytes!("../../../models/known.bin");
        ScoringEngine::from_bytes(model, curve, Some(known)).map_err(|e| e.to_string())
    });
    match res {
        Ok(e) => Ok(e),
        Err(s) => Err(AnalyzeError::NoModel(s.clone())),
    }
}

#[cfg(not(feature = "embedded-model"))]
fn embedded_engine() -> Result<&'static ScoringEngine, AnalyzeError> {
    Err(AnalyzeError::NoModel(
        "crate built without `embedded-model` feature".into(),
    ))
}

/// Resolve engine: explicit > embedded > none (caller should skip scoring).
fn resolve_engine<'a>(
    engine: Option<&'a ScoringEngine>,
) -> Result<Option<&'a ScoringEngine>, AnalyzeError> {
    if let Some(e) = engine {
        return Ok(Some(e));
    }
    match embedded_engine() {
        Ok(e) => Ok(Some(e)),
        Err(AnalyzeError::NoModel(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Check breach status only.
pub fn check_pwned<H: HttpGet>(
    password: &str,
    options: &AnalyzeOptions,
    http: &H,
) -> Result<BreachResult, AnalyzeError> {
    match options.breach_policy {
        BreachPolicy::Skip => Ok(BreachResult::skipped()),
        BreachPolicy::Check => {
            if let Some(ref path) = options.hibp_offline_path {
                Ok(hibp::check_pwned_offline(
                    password,
                    Path::new(path.as_str()),
                )?)
            } else {
                Ok(hibp::check_pwned(password, &options.user_agent, http)?)
            }
        }
    }
}

/// Full advisory analysis with a provided scoring engine and HTTP client.
///
/// Training-dependent Markov/MC scoring runs only when:
/// - `options.skip_model` is false, and
/// - an `engine` is passed, or the `embedded-model` feature is enabled.
///
/// Otherwise returns HIBP (optional) + `keyspace_bits` with `reasons` noting the skip.
pub fn analyze_with<H: HttpGet>(
    password: &str,
    options: &AnalyzeOptions,
    http: &H,
    engine: Option<&ScoringEngine>,
) -> Result<AnalyzeResult, AnalyzeError> {
    let cbits = keyspace_bits(password);

    if password.is_empty() {
        return Ok(AnalyzeResult {
            advisory: true,
            aborted: false,
            breach: BreachResult::skipped(),
            guess_number: Some(1.0),
            strength_bits: Some(0.0),
            keyspace_bits: cbits,
            label: Some(StrengthLabel::Weak),
            reasons: vec!["empty_password".to_string()],
        });
    }

    let breach = check_pwned(password, options, http)?;
    if breach.pwned {
        return Ok(AnalyzeResult::pwned_abort(breach, cbits));
    }

    if options.skip_model {
        return Ok(model_skipped_result(breach, cbits, "model_skipped"));
    }

    match resolve_engine(engine)? {
        Some(eng) => {
            let (guesses, bits, label, reasons) = eng.score_password(password);
            Ok(AnalyzeResult {
                advisory: true,
                aborted: false,
                breach,
                guess_number: Some(guesses),
                strength_bits: Some(bits),
                keyspace_bits: cbits,
                label: Some(label),
                reasons,
            })
        }
        None => Ok(model_skipped_result(breach, cbits, "model_unavailable")),
    }
}

/// Offline analysis: no network. Optional local HIBP via `hibp_offline_path`.
pub fn analyze_offline(
    password: &str,
    engine: Option<&ScoringEngine>,
) -> Result<AnalyzeResult, AnalyzeError> {
    analyze_offline_with(
        password,
        engine,
        AnalyzeOptions {
            breach_policy: BreachPolicy::Skip,
            skip_model: false,
            ..AnalyzeOptions::default()
        },
    )
}

/// Offline analysis with options. Network HIBP is never used; if
/// `hibp_offline_path` is set and `breach_policy` is [`BreachPolicy::Check`],
/// the local PwnedPasswordsDownloader store is consulted.
pub fn analyze_offline_with(
    password: &str,
    engine: Option<&ScoringEngine>,
    mut options: AnalyzeOptions,
) -> Result<AnalyzeResult, AnalyzeError> {
    if options.hibp_offline_path.is_none() {
        options.breach_policy = BreachPolicy::Skip;
    }
    analyze_with(password, &options, &NullHttp, engine)
}

/// Native helper using blocking HTTP.
#[cfg(feature = "native-http")]
pub fn analyze(
    password: &str,
    options: &AnalyzeOptions,
    engine: Option<&ScoringEngine>,
) -> Result<AnalyzeResult, AnalyzeError> {
    let http = hibp::NativeHttp {
        timeout_ms: options.timeout_ms,
    };
    analyze_with(password, options, &http, engine)
}

/// HTTP client that always fails — only used when breach is skipped.
struct NullHttp;
impl HttpGet for NullHttp {
    fn get_text(
        &self,
        _url: &str,
        _headers: &[(&str, &str)],
    ) -> Result<String, HibpError> {
        Err(HibpError::Http(
            "NullHttp: breach check skipped".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hibp::HttpGet;

    struct MockHttp;
    impl HttpGet for MockHttp {
        fn get_text(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
        ) -> Result<String, HibpError> {
            Ok(String::new())
        }
    }

    #[test]
    fn skip_model_returns_keyspace_only() {
        let opts = AnalyzeOptions {
            breach_policy: BreachPolicy::Skip,
            skip_model: true,
            ..AnalyzeOptions::default()
        };
        let r = analyze_with("Secret123!", &opts, &MockHttp, None).unwrap();
        assert!(r.guess_number.is_none());
        assert!(r.strength_bits.is_none());
        assert!(r.label.is_none());
        assert!(r.keyspace_bits > 0.0);
        assert!(r.reasons.iter().any(|x| x == "model_skipped"));
    }
}
