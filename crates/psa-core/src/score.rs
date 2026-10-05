//! Map guess numbers to strength bits and labels.

use crate::types::StrengthLabel;

/// Primary strength bits from estimated guess number.
pub fn strength_bits(guess_number: f64) -> f64 {
    guess_number.max(1.0).log2()
}

/// Label thresholds on strength_bits (safe bias: prefer weaker labels).
///
/// Anchored to published attack budgets (stricter than zxcvbn’s signup bands):
/// - &lt; ~35 bits: slightly above the ~10¹⁰ / ~33-bit offline *slow*-hash floor
///   (Wheeler/zxcvbn score-4), so “fair” is not granted at the bare minimum.
/// - &lt; ~48 bits (~10¹⁴ guesses): around Florêncio & Herley offline “probable safety”.
/// - &lt; ~66 bits (~10²⁰ guesses): below a fast-offline / GPU-class ballpark.
/// Advisory UX only — not authorization.
pub fn label_from_strength_bits(bits: f64) -> StrengthLabel {
    if bits < 35.0 {
        StrengthLabel::Weak
    } else if bits < 48.0 {
        StrengthLabel::Fair
    } else if bits < 66.0 {
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
        assert_eq!(label_from_strength_bits(35.0), StrengthLabel::Fair);
        assert_eq!(label_from_strength_bits(48.0), StrengthLabel::Strong);
        assert_eq!(label_from_strength_bits(66.0), StrengthLabel::VeryStrong);
    }
}
