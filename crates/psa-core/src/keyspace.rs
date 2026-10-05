//! Combinatorial keyspace size in bits: log2(base^length).
//!
//! Assumes an attacker brute-forces uniformly over the character classes that
//! appear in the password. This is **not** a measure of real-world guessability
//! for human-chosen passwords (see `strength_bits` / the Markov model).

const LOWER: u64 = 26;
const UPPER: u64 = 26;
const DIGITS: u64 = 10;
/// Printable ASCII symbols commonly counted in password validators.
const SYMBOLS: u64 = 32;

/// Characters treated as the "symbol" set (printable ASCII specials).
fn is_symbol(c: char) -> bool {
    matches!(
        c,
        '!' | '"'
            | '#'
            | '$'
            | '%'
            | '&'
            | '\''
            | '('
            | ')'
            | '*'
            | '+'
            | ','
            | '-'
            | '.'
            | '/'
            | ':'
            | ';'
            | '<'
            | '='
            | '>'
            | '?'
            | '@'
            | '['
            | '\\'
            | ']'
            | '^'
            | '_'
            | '`'
            | '{'
            | '|'
            | '}'
            | '~'
    )
}

/// Returns `(alphabet_base, length, keyspace_bits)`.
pub fn keyspace_estimate(password: &str) -> (u64, usize, f64) {
    let length = password.chars().count();
    if length == 0 {
        return (0, 0, 0.0);
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut other = 0u64;
    let mut seen_other = std::collections::BTreeSet::new();

    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if is_symbol(c) {
            has_symbol = true;
        } else if seen_other.insert(c) {
            other += 1;
        }
    }

    let mut base = 0u64;
    if has_lower {
        base += LOWER;
    }
    if has_upper {
        base += UPPER;
    }
    if has_digit {
        base += DIGITS;
    }
    if has_symbol {
        base += SYMBOLS;
    }
    base += other;

    if base == 0 {
        return (0, length, 0.0);
    }

    // log2(base^length) = length * log2(base)
    let bits = (length as f64) * (base as f64).log2();
    (base, length, bits)
}

/// Convenience: only the bit value (`log2` of the combinatorial keyspace).
pub fn keyspace_bits(password: &str) -> f64 {
    keyspace_estimate(password).2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_only() {
        let (base, len, bits) = keyspace_estimate("abcdef");
        assert_eq!(base, 26);
        assert_eq!(len, 6);
        let expected = 6.0 * 26f64.log2();
        assert!((bits - expected).abs() < 1e-9);
    }

    #[test]
    fn mixed_sets() {
        let (base, _, _) = keyspace_estimate("Ab1!");
        assert_eq!(base, 26 + 26 + 10 + 32);
    }

    #[test]
    fn empty() {
        let (base, len, bits) = keyspace_estimate("");
        assert_eq!(base, 0);
        assert_eq!(len, 0);
        assert_eq!(bits, 0.0);
    }
}
