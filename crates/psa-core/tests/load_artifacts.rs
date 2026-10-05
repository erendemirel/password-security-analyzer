#[test]
fn load_disk_artifacts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models");
    let eng = psa_core::ScoringEngine::from_paths(
        root.join("markov4.bin"),
        root.join("mc_curve.bin"),
        Some(root.join("known.bin").as_path()),
    );
    match &eng {
        Ok(_) => {}
        Err(e) => panic!("load failed: {e}"),
    }
    let e = eng.unwrap();
    let (_g, _b, label, reasons) = e.score_password("password");
    assert!(reasons.iter().any(|r| r == "known_from_training") || label == psa_core::StrengthLabel::Weak, "{label:?} {reasons:?}");
}
