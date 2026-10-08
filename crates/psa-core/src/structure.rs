//! Structured-constant detectors (safe demotion only).
//!
//! Catches whole-password shapes that look high-entropy to Markov but are
//! public identifiers or encoded constants: UUIDs, MAC, IPv4, hex digests,
//! dates, phone numbers, base64. Also demotes whitespace-only strings.

/// Demotion reasons for structured constants (empty if none).
pub fn structure_demotion_reasons(password: &str) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if looks_like_whitespace_only(password) {
        reasons.push("whitespace_only");
    }
    if looks_like_uuid(password) {
        reasons.push("structured_uuid");
    }
    if looks_like_mac(password) {
        reasons.push("structured_mac");
    }
    if looks_like_ipv4(password) {
        reasons.push("structured_ipv4");
    }
    if looks_like_hex_digest(password) {
        reasons.push("structured_hex");
    }
    if looks_like_date(password) {
        reasons.push("structured_date");
    }
    if looks_like_phone(password) {
        reasons.push("structured_phone");
    }
    if looks_like_base64(password) {
        reasons.push("structured_base64");
    }
    reasons
}

/// Cap label at Weak when the whole password is a structured constant.
pub fn apply_structure_demotion(
    label: crate::types::StrengthLabel,
    password: &str,
) -> (crate::types::StrengthLabel, Vec<&'static str>) {
    use crate::types::StrengthLabel;
    let reasons = structure_demotion_reasons(password);
    if reasons.is_empty() {
        return (label, reasons);
    }
    (StrengthLabel::Weak, reasons)
}

fn looks_like_whitespace_only(password: &str) -> bool {
    !password.is_empty() && password.chars().all(|c| c.is_whitespace())
}

fn looks_like_uuid(password: &str) -> bool {
    let s = password.trim();
    if s.len() == 36 {
        let b = s.as_bytes();
        if b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-' {
            return s
                .chars()
                .enumerate()
                .all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit());
        }
    }
    false
}

fn looks_like_mac(password: &str) -> bool {
    let s = password.trim();
    if s.len() != 17 {
        return false;
    }
    let sep = s.as_bytes()[2];
    if sep != b':' && sep != b'-' {
        return false;
    }
    let parts: Vec<&str> = s.split(sep as char).collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn looks_like_ipv4(password: &str) -> bool {
    let s = password.trim();
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        if p.is_empty() || p.len() > 3 || !p.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if p.len() > 1 && p.starts_with('0') {
            return false;
        }
        p.parse::<u8>().is_ok()
    })
}

fn looks_like_hex_digest(password: &str) -> bool {
    let s = password.trim();
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn plausible_ymd(y: u32, m: u32, d: u32) -> bool {
    if !(1900..=2100).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return false;
    }
    let max_d = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
            if leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    d <= max_d
}

/// Whole-password calendar dates (common leak / form formats).
fn looks_like_date(password: &str) -> bool {
    let s = password.trim();
    // YYYYMMDD
    if s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()) {
        let y: u32 = s[0..4].parse().unwrap_or(0);
        let m: u32 = s[4..6].parse().unwrap_or(0);
        let d: u32 = s[6..8].parse().unwrap_or(0);
        return plausible_ymd(y, m, d);
    }
    // YYYY-MM-DD or YYYY/MM/DD
    if s.len() == 10 {
        let b = s.as_bytes();
        let sep = b[4];
        if (sep == b'-' || sep == b'/') && b[7] == sep {
            let y: u32 = s[0..4].parse().unwrap_or(0);
            let m: u32 = s[5..7].parse().unwrap_or(0);
            let d: u32 = s[8..10].parse().unwrap_or(0);
            if plausible_ymd(y, m, d) {
                return true;
            }
        }
        // MM-DD-YYYY or DD-MM-YYYY (or /)
        let sep = b[2];
        if (sep == b'-' || sep == b'/') && b[5] == sep {
            let a: u32 = s[0..2].parse().unwrap_or(0);
            let c: u32 = s[3..5].parse().unwrap_or(0);
            let y: u32 = s[6..10].parse().unwrap_or(0);
            // Accept either MDY or DMY when both plausible, or uniquely one.
            if plausible_ymd(y, a, c) || plausible_ymd(y, c, a) {
                return true;
            }
        }
    }
    false
}

/// US-style phone numbers (10 digits, optional leading country 1).
fn looks_like_phone(password: &str) -> bool {
    let s = password.trim();
    if s.is_empty() {
        return false;
    }
    // Must look phone-shaped: mostly digits with optional phone punctuation.
    if !s
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '(' | ')' | '.' | ' '))
    {
        return false;
    }
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    let d = digits.as_str();
    // +1 / leading 1 then 10 digits, or plain 10 digits
    let national = if d.len() == 11 && d.starts_with('1') {
        &d[1..]
    } else if d.len() == 10 {
        d
    } else {
        return false;
    };
    // Area code should not start with 0 (keeps obvious non-phones out).
    // Exchange may start with 1 — fictional 555-123-4567 is a common password shape.
    if national.as_bytes()[0] < b'2' {
        return false;
    }
    let _ = national;
    true
}

/// Whole-password base64 (ASCII).
///
/// `+`, `/`, and `=` are outside a normal password alphabet, so those forms are
/// demoted from length 12. A pure alphanumeric block is also a legal password,
/// so it is demoted only when it decodes to printable text (encoded constants
/// such as `dGVzdHRlc3R0ZXN0` → `testtesttest`). Random alnum strings decode to
/// binary and are left alone.
fn looks_like_base64(password: &str) -> bool {
    let s = password.trim();
    if s.len() < 12 || s.len() % 4 != 0 {
        return false;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return false;
    }
    let stripped = s.trim_end_matches('=');
    if stripped.chars().any(|c| c == '=') {
        return false;
    }
    let pad = s.len() - stripped.len();
    if pad > 2 {
        return false;
    }
    let has_special = s.contains('+') || s.contains('/') || pad > 0;
    if has_special {
        return true;
    }
    // Pure alnum: length 16+ and a printable payload, not merely a legal alphabet.
    s.len() >= 16 && decoded_base64_is_text(stripped)
}

fn base64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard base64 of `s` (no padding) is entirely printable ASCII or common whitespace.
fn decoded_base64_is_text(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return false;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks_exact(4) {
        let Some(a) = base64_value(chunk[0]) else {
            return false;
        };
        let Some(b) = base64_value(chunk[1]) else {
            return false;
        };
        let Some(c) = base64_value(chunk[2]) else {
            return false;
        };
        let Some(d) = base64_value(chunk[3]) else {
            return false;
        };
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
    }
    !out.is_empty()
        && out
            .iter()
            .all(|b| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::StrengthLabel;

    #[test]
    fn whitespace_only() {
        assert!(looks_like_whitespace_only("     "));
        assert!(looks_like_whitespace_only("\t\t"));
        assert!(!looks_like_whitespace_only("a b"));
        let (l, r) = apply_structure_demotion(StrengthLabel::VeryStrong, "     ");
        assert_eq!(l, StrengthLabel::Weak);
        assert!(r.contains(&"whitespace_only"));
    }

    #[test]
    fn nil_uuid() {
        let u = "550e8400-e29b-41d4-a716-446655440000";
        assert!(looks_like_uuid(u));
        let (l, r) = apply_structure_demotion(StrengthLabel::VeryStrong, u);
        assert_eq!(l, StrengthLabel::Weak);
        assert!(r.contains(&"structured_uuid"));
    }

    #[test]
    fn mac_addr() {
        assert!(looks_like_mac("00:1A:2B:3C:4D:5E"));
        assert!(looks_like_mac("00-1a-2b-3c-4d-5e"));
        let (_, r) = apply_structure_demotion(StrengthLabel::Strong, "00:1A:2B:3C:4D:5E");
        assert!(r.contains(&"structured_mac"));
    }

    #[test]
    fn ipv4() {
        assert!(looks_like_ipv4("192.168.1.1"));
        assert!(!looks_like_ipv4("192.168.1.256"));
        assert!(!looks_like_ipv4("192.168.01.1"));
    }

    #[test]
    fn hex_digest() {
        assert!(looks_like_hex_digest("5f4dcc3b5aa765d61d8327deb882cf99"));
        assert!(looks_like_hex_digest(
            "a7f3c91e0b2d4468e1a9c0ffa7f3c91e0b2d4468e1a9c0ffa7f3c91e0b2d4468"
        ));
        assert!(!looks_like_hex_digest("kR7!mQx#9vLp$2nW"));
    }

    #[test]
    fn dates() {
        assert!(looks_like_date("20190315"));
        assert!(looks_like_date("2019-03-15"));
        assert!(looks_like_date("03/15/2019"));
        assert!(looks_like_date("15-03-2019"));
        assert!(!looks_like_date("20191345"));
        assert!(!looks_like_date("password"));
        let (_, r) = apply_structure_demotion(StrengthLabel::Strong, "20190315");
        assert!(r.contains(&"structured_date"));
    }

    #[test]
    fn phones() {
        assert!(looks_like_phone("5551234567"));
        assert!(looks_like_phone("555-123-4567"));
        assert!(looks_like_phone("(555)1234567"));
        assert!(looks_like_phone("+1 555 123 4567"));
        assert!(!looks_like_phone("0123456789")); // area can't start 0
        assert!(!looks_like_phone("kR7!mQx#9vLp$2nW"));
        let (_, r) = apply_structure_demotion(StrengthLabel::VeryStrong, "(555)1234567");
        assert!(r.contains(&"structured_phone"));
    }

    #[test]
    fn base64_shaped() {
        assert!(looks_like_base64("SGVsbG8gV29ybGQ="));
        assert!(looks_like_base64("YWJjZGVmZ2hpams="));
        assert!(looks_like_base64("dGVzdHRlc3R0ZXN0")); // base64("testtesttest")
        assert!(!looks_like_base64("correcthorsebatterystaple"));
        assert!(!looks_like_base64("short"));
        // Mixed-case alnum of a legal base64 length is not an encoded constant.
        assert!(!looks_like_base64("Mb2nPq9xLf4vRk7w"));
        assert!(!looks_like_base64("Mb2nPq9xLf4vRk7wXyZa"));
        let (_, r) = apply_structure_demotion(StrengthLabel::VeryStrong, "SGVsbG8gV29ybGQ=");
        assert!(r.contains(&"structured_base64"));
        let (_, random) = apply_structure_demotion(StrengthLabel::VeryStrong, "Mb2nPq9xLf4vRk7w");
        assert!(random.is_empty());
    }

    #[test]
    fn novel_random_ok() {
        let (_, r) = apply_structure_demotion(StrengthLabel::VeryStrong, "kR7!mQx#9vLp$2nW");
        assert!(r.is_empty());
    }
}
