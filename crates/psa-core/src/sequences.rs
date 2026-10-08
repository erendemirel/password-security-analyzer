//! Structural sequence / repeat / density detectors (safe demotion only).
//!
//! Addresses Markov blind spots: alphabetic runs, constant-gap sequences,
//! tiled fragments, mono-class blocks, and low character variety.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharClass {
    Lower,
    Upper,
    Digit,
    Other,
}

fn char_class(c: char) -> CharClass {
    if c.is_ascii_lowercase() {
        CharClass::Lower
    } else if c.is_ascii_uppercase() {
        CharClass::Upper
    } else if c.is_ascii_digit() {
        CharClass::Digit
    } else {
        CharClass::Other
    }
}

/// Longest run of consecutive codepoints stepping by `±1` (case-insensitive letters or digits).
pub fn longest_monotonic_run(password: &str) -> usize {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < 2 {
        return chars.len();
    }
    let mut best = 1usize;
    let mut cur = 1usize;
    let mut prev_delta: Option<i32> = None;

    for w in chars.windows(2) {
        let a = normalize(w[0]);
        let b = normalize(w[1]);
        let delta = match (a, b) {
            (Some(x), Some(y)) => y - x,
            _ => {
                cur = 1;
                prev_delta = None;
                continue;
            }
        };
        if delta == 1 || delta == -1 {
            if prev_delta.is_none() || prev_delta == Some(delta) {
                cur += 1;
                prev_delta = Some(delta);
                best = best.max(cur);
            } else {
                cur = 2;
                prev_delta = Some(delta);
                best = best.max(cur);
            }
        } else {
            cur = 1;
            prev_delta = None;
        }
    }
    best
}

fn normalize(c: char) -> Option<i32> {
    if c.is_ascii_alphabetic() {
        Some(c.to_ascii_lowercase() as i32)
    } else if c.is_ascii_digit() {
        Some(c as i32)
    } else {
        None
    }
}

/// Longest run with a constant non-zero gap (e.g. `acegik`, `97531`).
pub fn longest_constant_gap_run(password: &str) -> usize {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < 2 {
        return chars.len();
    }
    let mut best = 1usize;
    let mut cur = 1usize;
    let mut gap: Option<i32> = None;

    for w in chars.windows(2) {
        let a = normalize(w[0]);
        let b = normalize(w[1]);
        match (a, b) {
            (Some(x), Some(y)) => {
                let d = y - x;
                // Exclude ±1 (handled by monotonic) and 0 (repeats).
                if d.abs() >= 2 {
                    if gap == Some(d) {
                        cur += 1;
                    } else {
                        cur = 2;
                        gap = Some(d);
                    }
                    best = best.max(cur);
                } else {
                    cur = 1;
                    gap = None;
                }
            }
            _ => {
                cur = 1;
                gap = None;
            }
        }
    }
    best
}

/// Longest run of the same character.
pub fn longest_repeat_run(password: &str) -> usize {
    let mut best = 0usize;
    let mut cur = 0usize;
    let mut prev: Option<char> = None;
    for c in password.chars() {
        if Some(c) == prev {
            cur += 1;
        } else {
            cur = 1;
            prev = Some(c);
        }
        best = best.max(cur);
    }
    best
}

/// Longest run of characters in the same ASCII class (lower / upper / digit).
fn longest_class_run(password: &str) -> (usize, Option<CharClass>) {
    let mut best = 0usize;
    let mut best_class = None;
    let mut cur = 0usize;
    let mut prev: Option<CharClass> = None;
    for c in password.chars() {
        let cl = char_class(c);
        if cl == CharClass::Other {
            cur = 0;
            prev = None;
            continue;
        }
        if Some(cl) == prev {
            cur += 1;
        } else {
            cur = 1;
            prev = Some(cl);
        }
        if cur > best {
            best = cur;
            best_class = Some(cl);
        }
    }
    (best, best_class)
}

/// True when the password is made of the same fragment tiled ≥2 times (e.g. `abcabcabc`).
pub fn has_tiled_fragment(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    let n = chars.len();
    if n < 6 {
        return false;
    }
    // Whole-string exact tiling: frag repeated k≥2 times.
    for frag_len in 3..=(n / 2) {
        if n % frag_len != 0 {
            continue;
        }
        let tiles = n / frag_len;
        if tiles < 2 {
            continue;
        }
        let frag = &chars[..frag_len];
        if (0..tiles).all(|t| &chars[t * frag_len..(t + 1) * frag_len] == frag) {
            return true;
        }
    }
    // Also: ≥3 consecutive identical windows of length ≥3 (covers leading noise).
    for frag_len in 3..=(n / 3) {
        let mut i = 0usize;
        while i + frag_len * 3 <= n {
            let a = &chars[i..i + frag_len];
            let b = &chars[i + frag_len..i + frag_len * 2];
            let c = &chars[i + frag_len * 2..i + frag_len * 3];
            if a == b && b == c {
                return true;
            }
            i += 1;
        }
    }
    false
}

/// Unique-character ratio (0..=1).
pub fn unique_char_ratio(password: &str) -> f64 {
    let n = password.chars().count();
    if n == 0 {
        return 0.0;
    }
    let mut uniq = std::collections::HashSet::new();
    for c in password.chars() {
        uniq.insert(c);
    }
    uniq.len() as f64 / n as f64
}

/// QWERTY adjacency (letters + digits + common shifted digits), case-insensitive letters.
fn keyboard_neighbors() -> &'static [(char, &'static [char])] {
    &[
        ('1', &['2', 'q', '!']),
        ('2', &['1', '3', 'q', 'w', '@']),
        ('3', &['2', '4', 'w', 'e', '#']),
        ('4', &['3', '5', 'e', 'r', '$']),
        ('5', &['4', '6', 'r', 't', '%']),
        ('6', &['5', '7', 't', 'y', '^']),
        ('7', &['6', '8', 'y', 'u', '&']),
        ('8', &['7', '9', 'u', 'i', '*']),
        ('9', &['8', '0', 'i', 'o', '(']),
        ('0', &['9', 'o', 'p', ')']),
        ('q', &['1', '2', 'w', 'a']),
        ('w', &['2', '3', 'q', 'e', 'a', 's']),
        ('e', &['3', '4', 'w', 'r', 's', 'd']),
        ('r', &['4', '5', 'e', 't', 'd', 'f']),
        ('t', &['5', '6', 'r', 'y', 'f', 'g']),
        ('y', &['6', '7', 't', 'u', 'g', 'h']),
        ('u', &['7', '8', 'y', 'i', 'h', 'j']),
        ('i', &['8', '9', 'u', 'o', 'j', 'k']),
        ('o', &['9', '0', 'i', 'p', 'k', 'l']),
        ('p', &['0', 'o', 'l']),
        ('a', &['q', 'w', 's', 'z']),
        ('s', &['w', 'e', 'a', 'd', 'z', 'x']),
        ('d', &['e', 'r', 's', 'f', 'x', 'c']),
        ('f', &['r', 't', 'd', 'g', 'c', 'v']),
        ('g', &['t', 'y', 'f', 'h', 'v', 'b']),
        ('h', &['y', 'u', 'g', 'j', 'b', 'n']),
        ('j', &['u', 'i', 'h', 'k', 'n', 'm']),
        ('k', &['i', 'o', 'j', 'l', 'm']),
        ('l', &['o', 'p', 'k']),
        ('z', &['a', 's', 'x']),
        ('x', &['s', 'd', 'z', 'c']),
        ('c', &['d', 'f', 'x', 'v']),
        ('v', &['f', 'g', 'c', 'b']),
        ('b', &['g', 'h', 'v', 'n']),
        ('n', &['h', 'j', 'b', 'm']),
        ('m', &['j', 'k', 'n']),
        ('!', &['1', '2', '@']),
        ('@', &['2', '!', '#']),
        ('#', &['3', '@', '$']),
        ('$', &['4', '#', '%']),
        ('%', &['5', '$', '^']),
        ('^', &['6', '%', '&']),
        ('&', &['7', '^', '*']),
        ('*', &['8', '&', '(']),
        ('(', &['9', '*', ')']),
        (')', &['0', '(']),
    ]
}

fn norm_key(c: char) -> char {
    if c.is_ascii_alphabetic() {
        c.to_ascii_lowercase()
    } else {
        c
    }
}

fn keys_adjacent(a: char, b: char) -> bool {
    let a = norm_key(a);
    let b = norm_key(b);
    if a == b {
        return true;
    }
    for (k, neigh) in keyboard_neighbors() {
        if *k == a && neigh.contains(&b) {
            return true;
        }
    }
    false
}

/// Longest run of QWERTY-adjacent keys (spatial walk / zigzag).
pub fn longest_keyboard_walk(password: &str) -> usize {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < 2 {
        return chars.len();
    }
    let mut best = 1usize;
    let mut cur = 1usize;
    for w in chars.windows(2) {
        if keys_adjacent(w[0], w[1]) {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 1;
        }
    }
    best
}

/// Fraction of consecutive pairs that are QWERTY-adjacent (0..=1).
pub fn keyboard_adjacency_ratio(password: &str) -> f64 {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < 2 {
        return 0.0;
    }
    let mut ok = 0usize;
    let mut total = 0usize;
    for w in chars.windows(2) {
        total += 1;
        if keys_adjacent(w[0], w[1]) {
            ok += 1;
        }
    }
    ok as f64 / total as f64
}

/// True when most of the password is a keyboard walk (safe demotion).
pub fn has_keyboard_walk(password: &str) -> bool {
    let n = password.chars().count();
    if n < 5 {
        return false;
    }
    let walk = longest_keyboard_walk(password);
    let ratio = keyboard_adjacency_ratio(password);
    // Whole-password walk, long contiguous walk, or high adjacency
    // (covers concatenated columns like `1qaz2wsx` where z→2 breaks the run).
    walk >= n || (walk >= 6 && walk * 5 >= n * 4) || (n >= 6 && ratio >= 0.8)
}

/// Reasons that should demote strength (empty if none).
pub fn sequence_demotion_reasons(password: &str) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    let mono = longest_monotonic_run(password);
    let gap = longest_constant_gap_run(password);
    let rep = longest_repeat_run(password);
    let (class_run, class) = longest_class_run(password);
    let n = password.chars().count();

    // 8+ consecutive alpha/digit steps ≈ alphabet / 12345678
    if mono >= 8 {
        reasons.push("sequential_run");
    }
    // Constant gap ≥6 (acegik…)
    if gap >= 6 {
        reasons.push("constant_gap");
    }
    if rep >= 6 {
        reasons.push("repeated_chars");
    }
    // Mono-class blocks: long digit runs always; long alpha only with low variety
    // (avoids demoting diceware-style all-lowercase passphrases).
    let variety = unique_char_ratio(password);
    match class {
        Some(CharClass::Digit) if class_run >= 12 => reasons.push("class_run"),
        Some(CharClass::Lower) | Some(CharClass::Upper) if class_run >= 20 && variety <= 0.4 => {
            reasons.push("class_run")
        }
        _ => {}
    }
    if has_tiled_fragment(password) {
        reasons.push("tiled_fragment");
    }
    if has_keyboard_walk(password) {
        reasons.push("keyboard_walk");
    }
    // Low variety on longer passwords (demote-only)
    if n >= 12 && unique_char_ratio(password) <= 0.25 {
        reasons.push("low_variety");
    }
    reasons
}

/// Cap label at Weak when strong sequential structure is present.
pub fn apply_sequence_demotion(
    label: crate::types::StrengthLabel,
    password: &str,
) -> (crate::types::StrengthLabel, Vec<&'static str>) {
    use crate::types::StrengthLabel;
    let reasons = sequence_demotion_reasons(password);
    if reasons.is_empty() {
        return (label, reasons);
    }
    (StrengthLabel::Weak, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::StrengthLabel;

    #[test]
    fn alphabet_is_sequential() {
        assert!(longest_monotonic_run("abcdefghijklmnopqrstuvwxyz") >= 26);
        let (l, r) =
            apply_sequence_demotion(StrengthLabel::VeryStrong, "abcdefghijklmnopqrstuvwxyz");
        assert_eq!(l, StrengthLabel::Weak);
        assert!(r.contains(&"sequential_run"));
    }

    #[test]
    fn keyboard_walks() {
        assert!(has_keyboard_walk("qwerty"));
        assert!(has_keyboard_walk("asdfgh"));
        assert!(has_keyboard_walk("1qaz2wsx"));
        assert!(has_keyboard_walk("qwerasdf"));
        assert!(has_keyboard_walk("zaq1xsw2"));
        assert!(longest_keyboard_walk("qwerty") >= 6);
        let (l, r) = apply_sequence_demotion(StrengthLabel::VeryStrong, "wertyuis");
        assert_eq!(l, StrengthLabel::Weak);
        assert!(r.contains(&"keyboard_walk"));
        // Normal word / passphrase should not trip spatial walk
        assert!(!has_keyboard_walk("password"));
        assert!(!has_keyboard_walk("correcthorsebatterystaple"));
    }

    #[test]
    fn digits_run() {
        assert!(longest_monotonic_run("1234567890") >= 9);
        assert!(longest_monotonic_run("12345678") >= 8);
    }

    #[test]
    fn constant_gap_acegik() {
        assert!(longest_constant_gap_run("acegik") >= 6);
        let (l, r) = apply_sequence_demotion(StrengthLabel::VeryStrong, "acegikmo");
        assert_eq!(l, StrengthLabel::Weak);
        assert!(r.contains(&"constant_gap"));
    }

    #[test]
    fn tiled_fragment() {
        assert!(has_tiled_fragment("abcabcabc"));
        assert!(has_tiled_fragment("xyzxyzxyzxyz"));
        assert!(!has_tiled_fragment("xK9#mP2$vL7q"));
        let (_, r) = apply_sequence_demotion(StrengthLabel::Strong, "passpasspass");
        assert!(r.contains(&"tiled_fragment"));
    }

    #[test]
    fn class_run_digits() {
        let (n, c) = longest_class_run("111222333444");
        assert!(n >= 12);
        assert_eq!(c, Some(CharClass::Digit));
        let (_, r) = apply_sequence_demotion(StrengthLabel::Strong, "111222333444");
        assert!(
            r.contains(&"class_run") || r.contains(&"low_variety") || r.contains(&"tiled_fragment")
        );
    }

    #[test]
    fn randomish_ok() {
        let pw = "xK9#mP2$vL7q";
        let (_, r) = apply_sequence_demotion(StrengthLabel::Strong, pw);
        assert!(r.is_empty(), "{r:?}");
    }
}
