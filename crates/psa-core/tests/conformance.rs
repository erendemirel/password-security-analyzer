//! Conformance runner for golden JSON vectors.

use psa_core::keyspace::keyspace_bits;
use psa_core::hibp::{hash_prefix_suffix, match_range_body};
use psa_core::analyze_offline;
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

#[derive(Deserialize)]
struct OfflineFile {
    cases: Vec<OfflineCase>,
}

#[derive(Deserialize)]
struct OfflineCase {
    id: String,
    password: String,
    expect: OfflineExpect,
}

#[derive(Deserialize)]
struct OfflineExpect {
    aborted: Option<bool>,
    label: Option<String>,
    label_in: Option<Vec<String>>,
    reasons_contains: Option<Vec<String>>,
    keyspace_bits: Option<f64>,
    keyspace_bits_approx: Option<f64>,
    min_keyspace_bits: Option<f64>,
}

#[cfg(feature = "embedded-model")]
#[test]
fn conformance_offline_scoring() {
    let path = conformance_dir().join("offline_scoring.json");
    let raw = fs::read_to_string(&path).expect("read offline_scoring.json");
    let file: OfflineFile = serde_json::from_str(&raw).unwrap();
    for case in file.cases {
        let r = analyze_offline(&case.password, None).expect(&case.id);
        if let Some(a) = case.expect.aborted {
            assert_eq!(r.aborted, a, "{}", case.id);
        }
        if let Some(label) = &case.expect.label {
            assert_eq!(
                r.label.map(|l| l.as_str().to_string()).as_deref(),
                Some(label.as_str()),
                "{}",
                case.id
            );
        }
        if let Some(labels) = &case.expect.label_in {
            let got = r.label.map(|l| l.as_str().to_string()).unwrap_or_default();
            assert!(
                labels.iter().any(|l| l == &got),
                "{}: got label {got}, want one of {labels:?}",
                case.id
            );
        }
        if let Some(needles) = &case.expect.reasons_contains {
            for n in needles {
                assert!(
                    r.reasons.iter().any(|x| x == n),
                    "{} missing reason {n}",
                    case.id
                );
            }
        }
        if let Some(bits) = case.expect.keyspace_bits {
            assert!(
                (r.keyspace_bits - bits).abs() < 1e-9,
                "{} keyspace_bits",
                case.id
            );
        }
        if let Some(bits) = case.expect.keyspace_bits_approx {
            assert!(
                (r.keyspace_bits - bits).abs() < 1e-6,
                "{} keyspace approx got {}",
                case.id,
                r.keyspace_bits
            );
        }
        if let Some(min_b) = case.expect.min_keyspace_bits {
            assert!(
                r.keyspace_bits + 1e-9 >= min_b,
                "{} min keyspace",
                case.id
            );
        }
        let _ = keyspace_bits(&case.password);
    }
}

#[cfg(not(feature = "embedded-model"))]
#[test]
fn conformance_offline_without_embedded_model() {
    let r = analyze_offline("password", None).unwrap();
    assert!(r.guess_number.is_none());
    assert!(r.label.is_none());
    assert!(r.keyspace_bits > 0.0);
    assert!(r.reasons.iter().any(|x| x == "model_unavailable"));
}

#[derive(Deserialize)]
struct HibpFile {
    cases: Vec<Value>,
}

#[test]
fn conformance_hibp_fixtures() {
    let path = conformance_dir().join("hibp_fixtures.json");
    let raw = fs::read_to_string(&path).unwrap();
    let file: HibpFile = serde_json::from_str(&raw).unwrap();
    for case in file.cases {
        let id = case["id"].as_str().unwrap();
        if case.get("password").is_some() {
            let pw = case["password"].as_str().unwrap();
            let (p, s) = hash_prefix_suffix(pw);
            assert_eq!(p, case["expect_prefix"].as_str().unwrap(), "{id}");
            assert_eq!(s, case["expect_suffix"].as_str().unwrap(), "{id}");
        } else {
            let suffix = case["suffix"].as_str().unwrap();
            let body = case["body"].as_str().unwrap();
            let got = match_range_body(body, suffix).unwrap();
            let exp = &case["expect_occurrences"];
            if exp.is_null() {
                assert!(got.is_none(), "{id}");
            } else {
                assert_eq!(got.unwrap(), exp.as_u64().unwrap(), "{id}");
            }
        }
    }
}
