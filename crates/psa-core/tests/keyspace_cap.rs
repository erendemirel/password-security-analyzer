//! Keyspace cap: model guess numbers must not exceed 2^keyspace_bits.

#[cfg(feature = "embedded-model")]
#[test]
fn short_random_looking_capped_by_keyspace() {
    use psa_core::{analyze_offline, StrengthLabel};

    for (pw, max_label) in [
        ("dj38sy", StrengthLabel::Weak),
        ("dj38sS", StrengthLabel::Weak),
        ("dj38syd", StrengthLabel::Fair),
        ("dj38syd_", StrengthLabel::Fair),
        ("xk9m2p", StrengthLabel::Weak),
    ] {
        let r = analyze_offline(pw, None).unwrap();
        let label = r.label.expect("label");
        assert!(
            label <= max_label,
            "{pw}: label {label:?} stronger than {max_label:?}"
        );
        let sb = r.strength_bits.expect("strength_bits");
        assert!(
            sb <= r.keyspace_bits + 1e-6,
            "{pw}: strength_bits {sb} > keyspace_bits {}",
            r.keyspace_bits
        );
        assert!(
            r.reasons.iter().any(|x| x == "capped_by_keyspace"),
            "{pw}: expected capped_by_keyspace in {:?}",
            r.reasons
        );
    }
}

#[cfg(feature = "embedded-model")]
#[test]
fn strength_bits_never_exceeds_keyspace() {
    use psa_core::analyze_offline;

    for pw in [
        "password",
        "correcthorsebatterystaple",
        "kR7!mQx#9vLp$2nW",
        "Ab1!",
        "20190315",
        "dj38sS_5",
    ] {
        let r = analyze_offline(pw, None).unwrap();
        if let Some(sb) = r.strength_bits {
            assert!(
                sb <= r.keyspace_bits + 1e-6,
                "{pw}: strength_bits {sb} > keyspace_bits {}",
                r.keyspace_bits
            );
        }
    }
}
