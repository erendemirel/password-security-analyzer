//! Map guess numbers to strength bits and labels.

use crate::types::StrengthLabel;

/// Primary strength bits from estimated guess number.
pub fn strength_bits(guess_number: f64) -> f64 {
    guess_number.max(1.0).log2()
}

/// Label thresholds on strength_bits (safe bias: prefer weaker labels).
/// Tuned for advisory UX, not authorization.
pub fn label_from_strength_bits(bits: f64) -> StrengthLabel {
    if bits < 28.0 {
        StrengthLabel::Weak
    } else if bits < 40.0 {
        StrengthLabel::Fair
    } else if bits < 56.0 {
        StrengthLabel::Strong
    } else {
        StrengthLabel::VeryStrong
    }
}

pub fn label_from_guess_number(guess_number: f64) -> StrengthLabel {
    label_from_strength_bits(strength_bits(guess_number))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_and_labels() {
        assert!((strength_bits(1024.0) - 10.0).abs() < 1e-9);
        assert_eq!(label_from_strength_bits(10.0), StrengthLabel::Weak);
        assert_eq!(label_from_strength_bits(30.0), StrengthLabel::Fair);
        assert_eq!(label_from_strength_bits(45.0), StrengthLabel::Strong);
        assert_eq!(label_from_strength_bits(60.0), StrengthLabel::VeryStrong);
    }
}
