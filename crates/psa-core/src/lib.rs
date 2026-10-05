//! Advisory password strength library (HIBP + Markov/Monte Carlo).
//!
//! This crate does **not** authorize account creation. Consumers must enforce
//! their own policy (e.g. Auth API basic checks).

#![forbid(unsafe_code)]

pub mod analyze;
pub mod keyspace;
pub mod hibp;
pub mod known;
pub mod model;
pub mod monte_carlo;
pub mod score;
pub mod sequences;
pub mod structure;
pub mod types;

pub use analyze::{
    analyze_offline, analyze_offline_with, analyze_with, check_pwned, has_embedded_model,
    AnalyzeError, ScoringEngine,
};
pub use keyspace::{keyspace_bits, keyspace_estimate};
pub use hibp::{
    check_pwned as hibp_check_pwned, check_pwned_offline, hash_prefix_suffix, HttpGet,
    OfflineHibpStore,
};
#[cfg(feature = "native-http")]
pub use hibp::NativeHttp;
pub use model::MarkovModel;
pub use monte_carlo::MonteCarloCurve;
pub use types::*;

#[cfg(feature = "native-http")]
pub use analyze::analyze;
