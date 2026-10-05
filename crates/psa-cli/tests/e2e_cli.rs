//! CLI end-to-end smoke: spawn the `psa` binary on a few passwords.

use std::path::PathBuf;
use std::process::Command;

fn psa_bin() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // crates
    p.pop(); // repo root
    let release = p.join("target/release/psa.exe");
    if release.exists() {
        return release;
    }
    let release_unix = p.join("target/release/psa");
    if release_unix.exists() {
        return release_unix;
    }
    // Fall back to the binary produced for this package in the same profile.
    PathBuf::from(env!("CARGO_BIN_EXE_psa"))
}

fn analyze_offline(password: &str) -> serde_json::Value {
    let out = Command::new(psa_bin())
        .args(["analyze-offline", password])
        .output()
        .expect("spawn psa");
    assert!(
        out.status.success(),
        "psa failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("json")
}

#[test]
fn cli_edge_alphabet_demoted() {
    let v = analyze_offline("abcdefghijklmnopqrstuvwxyz");
    assert_eq!(v["label"], "weak");
    let reasons = v["reasons"].as_array().unwrap();
    assert!(reasons.iter().any(|r| r == "sequential_run"));
}

#[test]
fn cli_iloveyou_not_strong() {
    let v = analyze_offline("iloveyou");
    let label = v["label"].as_str().unwrap_or("");
    assert!(
        matches!(label, "weak" | "fair"),
        "iloveyou label={label}"
    );
}

#[test]
fn cli_no_model_null_label() {
    let out = Command::new(psa_bin())
        .args(["analyze-offline", "password", "--no-model"])
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["label"].is_null());
    assert!(v["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r == "model_skipped"));
}

#[test]
fn cli_batch_ndjson() {
    let out = Command::new(psa_bin())
        .args(["analyze-offline", "--batch"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    // Write via child stdin
    let mut child = out;
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(stdin, "password").unwrap();
        writeln!(stdin).unwrap();
        writeln!(stdin, "#1bitch").unwrap();
        writeln!(stdin, "iloveyou").unwrap();
    }
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "psa failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<_> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3, "expected 3 NDJSON lines, got {:?}", lines);
    for line in lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("ndjson");
        assert!(v.get("label").is_some());
        assert!(v.get("guess_number").is_some());
    }
}
