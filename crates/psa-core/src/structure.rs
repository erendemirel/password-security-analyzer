//! Structured-constant detectors (safe demotion only).
//!
//! Catches whole-password shapes that look high-entropy to Markov but are
//! public identifiers: UUIDs, MAC addresses, IPv4, hex hash digests.
//! Also demotes whitespace-only strings (appear in leaks; Markov overrates).

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
    // 8-4-4-4-12 with hyphens
    if s.len() == 36 {
        let b = s.as_bytes();
        if b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-' {
            return s.chars().enumerate().all(|(i, c)| {
                matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit()
            });
        }
    }
    // 32 hex (UUID without hyphens) — only if not already counted as digest;
    // treated as uuid-shaped when we want the uuid reason specifically.
    if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        // Prefer structured_hex for plain digests; UUID-without-hyphens is still a digest.
        return false;
    }
    false
}

fn looks_like_mac(password: &str) -> bool {
    let s = password.trim();
    // AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
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
    parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
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
        // no leading zero unless the octet is exactly "0"
        if p.len() > 1 && p.starts_with('0') {
            return false;
        }
        p.parse::<u8>().is_ok()
    })
}

fn looks_like_hex_digest(password: &str) -> bool {
    let s = password.trim();
    // MD5=32, SHA-1=40, SHA-256=64 — whole password hex only
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
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
    fn novel_random_ok() {
        let (_, r) = apply_structure_demotion(StrengthLabel::VeryStrong, "kR7!mQx#9vLp$2nW");
        assert!(r.is_empty());
    }
}
