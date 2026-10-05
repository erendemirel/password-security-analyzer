#!/usr/bin/env python3
"""Expand tricky suite: fetch HIBP prefixes, score, rewrite corpus_tricky.json."""
from __future__ import annotations

import hashlib
import json
import subprocess
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
PSA = ROOT / "target" / "release" / "psa.exe"
RANGES = ROOT / "data" / "hibp" / "ranges"
UA = "password-security-analyzer/0.1 (tricky expand)"

# Existing + many new handcrafted cases
NEW_CASES: List[Dict[str, Any]] = [
    # strong / novel
    {"id": "tricky_fr_novel", "password": "brume-violon-quatorze-9!", "tags": ["tricky", "strongish", "fr"], "hope": "strong+"},
    {"id": "tricky_es_novel", "password": "niebla-castillo-farola-3#", "tags": ["tricky", "strongish", "es"], "hope": "strong+"},
    {"id": "tricky_jp_romaji_novel", "password": "kasumi-tsubaki-yoru-7!", "tags": ["tricky", "strongish", "ja"], "hope": "strong+"},
    {"id": "tricky_diceware5", "password": "maple.quartz.ember.willow.92", "tags": ["tricky", "strongish", "passphrase"], "hope": "strong+"},
    {"id": "tricky_mixed_script_novel", "password": "Securité-Δ9!kLm", "tags": ["tricky", "strongish", "unicode"], "hope": "strong+"},
    {"id": "tricky_emoji_suffix", "password": "orchid-lantern-84!", "tags": ["tricky", "strongish"], "hope": "strong+"},
    {"id": "tricky_long_hex_novel", "password": "a7f3c91e0b2d4468e1a9c0ff", "tags": ["tricky", "structured"], "hope": "strong+"},
    # classic traps (expect weak via HIBP/known)
    {"id": "tricky_letmein1", "password": "Letmein1!", "tags": ["tricky", "common"], "hope": "weak", "hibp": True},
    {"id": "tricky_monkey1", "password": "Monkey123", "tags": ["tricky", "common"], "hope": "weak", "hibp": True},
    {"id": "tricky_dragon2024", "password": "Dragon2024", "tags": ["tricky", "date"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_adminadmin", "password": "adminadmin", "tags": ["tricky", "common"], "hope": "weak", "hibp": True},
    {"id": "tricky_rootroot", "password": "rootroot", "tags": ["tricky", "common"], "hope": "weak", "hibp": True},
    {"id": "tricky_qazwsx", "password": "qazwsx", "tags": ["tricky", "keyboard"], "hope": "weak", "hibp": True},
    {"id": "tricky_zaq12wsx", "password": "zaq12wsx", "tags": ["tricky", "keyboard"], "hope": "weak", "hibp": True},
    {"id": "tricky_1q2w3e4r", "password": "1q2w3e4r", "tags": ["tricky", "keyboard"], "hope": "weak", "hibp": True},
    {"id": "tricky_starwars", "password": "Starwars1", "tags": ["tricky", "pop"], "hope": "weak", "hibp": True},
    {"id": "tricky_batman", "password": "Batman123", "tags": ["tricky", "pop"], "hope": "weak", "hibp": True},
    {"id": "tricky_pokemon", "password": "Pikachu1", "tags": ["tricky", "pop"], "hope": "weak", "hibp": True},
    {"id": "tricky_harry", "password": "HarryPotter", "tags": ["tricky", "pop"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_matrix", "password": "Matrix1999", "tags": ["tricky", "pop"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_spring2023", "password": "Spring2023!", "tags": ["tricky", "date"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_january1", "password": "January1", "tags": ["tricky", "date"], "hope": "weak", "hibp": True},
    {"id": "tricky_phone_us", "password": "5551234567", "tags": ["tricky", "digits"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_pin_1234", "password": "1234", "tags": ["tricky", "pin"], "hope": "weak", "hibp": True},
    {"id": "tricky_pin_000000", "password": "000000", "tags": ["tricky", "pin"], "hope": "weak", "hibp": True},
    {"id": "tricky_emailish", "password": "user@email.com", "tags": ["tricky", "identity"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_firstname_year", "password": "Jennifer1985", "tags": ["tricky", "identity"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_lorem", "password": "LoremIpsum", "tags": ["tricky", "common"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_changeme!", "password": "ChangeMe!", "tags": ["tricky", "common"], "hope": "weak", "hibp": True},
    {"id": "tricky_passw0rd!", "password": "Passw0rd!", "tags": ["tricky", "leet"], "hope": "weak", "hibp": True},
    {"id": "tricky_p@$$w0rd", "password": "P@$$w0rd", "tags": ["tricky", "leet"], "hope": "weak", "hibp": True},
    {"id": "tricky_iloveyou!", "password": "Iloveyou!", "tags": ["tricky", "phrase"], "hope": "weak", "hibp": True},
    {"id": "tricky_je_taime", "password": "JeT'aime", "tags": ["tricky", "phrase", "fr"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_tequiero1", "password": "Tequiero1", "tags": ["tricky", "phrase", "es"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_spaces_password", "password": "pass word", "tags": ["tricky", "common"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_all_ones", "password": "11111111", "tags": ["tricky", "repeat"], "hope": "weak", "hibp": True},
    {"id": "tricky_hexspeak", "password": "deadbeef", "tags": ["tricky", "hex"], "hope": "weak", "hibp": True},
    {"id": "tricky_cafebabe", "password": "cafebabe", "tags": ["tricky", "hex"], "hope": "weak", "hibp": True},
    {"id": "tricky_router_default", "password": "admin1234", "tags": ["tricky", "default"], "hope": "weak", "hibp": True},
    {"id": "tricky_wifi_default", "password": "password1234", "tags": ["tricky", "default"], "hope": "weak", "hibp": True},
    # structure / limitation probes
    {"id": "tricky_ipv4", "password": "192.168.1.1", "tags": ["tricky", "structured"], "hope": "observe"},
    {"id": "tricky_mac", "password": "00:1A:2B:3C:4D:5E", "tags": ["tricky", "structured"], "hope": "observe"},
    {"id": "tricky_jwt_header", "password": "eyJhbGciOiJIUzI1NiJ9", "tags": ["tricky", "structured"], "hope": "observe"},
    {"id": "tricky_creditcardish", "password": "4111111111111111", "tags": ["tricky", "digits"], "hope": "weak-fair", "hibp": True},
    {"id": "tricky_sqlish", "password": "' OR 1=1 --", "tags": ["tricky", "injection"], "hope": "observe"},
    {"id": "tricky_pathish", "password": "C:\\Windows\\System32", "tags": ["tricky", "structured"], "hope": "observe"},
    {"id": "tricky_md5_looking", "password": "5f4dcc3b5aa765d61d8327deb882cf99", "tags": ["tricky", "hash"], "hope": "observe"},
]


def sha_parts(pw: str):
    h = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    return h[:5], h[5:]


def ensure_range(pw: str) -> Optional[int]:
    RANGES.mkdir(parents=True, exist_ok=True)
    pref, suf = sha_parts(pw)
    dest = RANGES / f"{pref}.txt"
    if not dest.exists() or dest.stat().st_size == 0:
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{pref}",
            headers={"User-Agent": UA, "Add-Padding": "true"},
        )
        try:
            body = urllib.request.urlopen(req, timeout=60).read().decode()
            dest.write_text(body, encoding="utf-8")
        except Exception as e:
            print(f"FAIL fetch {pref} for {pw!r}: {e}")
            return None
    else:
        body = dest.read_text(encoding="utf-8", errors="ignore")
    for line in body.splitlines():
        if line.upper().startswith(suf + ":"):
            try:
                return int(line.split(":", 1)[1].strip())
            except ValueError:
                return None
    return None


def analyze(pw: str, use_hibp: bool) -> dict:
    cmd = [str(PSA), "analyze-offline", pw]
    if use_hibp:
        cmd += ["--hibp-offline", str(RANGES)]
    out = subprocess.check_output(cmd, text=True, encoding="utf-8")
    return json.loads(out)


def hope_ok(hope: str, label: Optional[str], aborted: bool) -> bool:
    rank = {"weak": 0, "fair": 1, "strong": 2, "very_strong": 3, None: -1}
    r = rank.get(label, -1)
    if hope == "observe":
        return True
    if hope == "weak":
        return aborted or r == 0
    if hope == "weak-fair":
        return aborted or r <= 1
    if hope == "strong+":
        return (not aborted) and r >= 2
    if hope == "very_strong":
        return (not aborted) and r >= 3
    if hope == "not_very_strong":
        return aborted or r < 3
    return True


def to_e2e_case(case: dict, result: dict) -> dict:
    """Build durable e2e expectation from observed score."""
    tags = list(case.get("tags") or ["tricky"])
    pw = case["password"]
    label = result.get("label")
    aborted = bool(result.get("aborted"))
    pwned = bool((result.get("breach") or {}).get("pwned"))
    bits = result.get("strength_bits")
    cbits = float(result.get("keyspace_bits") or 0)

    entry: Dict[str, Any] = {
        "id": case["id"],
        "password": pw,
        "tags": tags,
    }

    if pwned or aborted:
        entry["mode"] = "offline_hibp"
        entry["expect"] = {
            "aborted": True,
            "pwned": True,
            "max_label": "weak",
            "reasons_any": ["pwned_password"],
        }
        return entry

    # model-only
    hope = case.get("hope", "observe")
    expect: Dict[str, Any] = {}
    if hope == "strong+" and label in ("strong", "very_strong"):
        expect["min_label"] = "strong"
        if cbits >= 80:
            expect["min_keyspace_bits"] = int(cbits * 0.7)
    elif hope == "very_strong" and label == "very_strong":
        expect["min_label"] = "very_strong"
    elif hope in ("weak", "weak-fair") and label in ("weak", "fair"):
        expect["max_label"] = "fair" if hope == "weak-fair" else "weak"
    elif hope == "observe":
        # lock current ceiling so it can't silently become stronger
        if label:
            expect["max_label"] = label
        if cbits > 0:
            expect["min_keyspace_bits"] = max(1, int(cbits * 0.5))
        tags = tags + (["known-limitation"] if label == "very_strong" else [])
        entry["tags"] = tags
    else:
        # fallback: don't allow stronger than observed
        if label:
            expect["max_label"] = label

    if bits is not None and label in ("strong", "very_strong") and "min_label" in expect:
        pass
    entry["expect"] = expect
    return entry


def main() -> None:
    if not PSA.exists():
        raise SystemExit(f"missing {PSA}")

    # load existing corpus_tricky to keep prior cases
    corpus_path = ROOT / "e2e" / "corpus_tricky.json"
    existing = json.loads(corpus_path.read_text(encoding="utf-8"))
    by_id = {c["id"]: c for c in existing.get("cases", [])}

    print(f"{'id':32} {'label':12} {'hibp':5} {'hope':8} ok?")
    print("-" * 80)
    scored_rows = []
    mismatches = 0

    for case in NEW_CASES:
        pw = case["password"]
        want_hibp = bool(case.get("hibp")) or case.get("hope") in (
            "weak",
            "weak-fair",
            "not_very_strong",
        )
        count = ensure_range(pw)
        result = analyze(pw, use_hibp=True)
        aborted = bool(result.get("aborted"))
        label = result.get("label")
        pwned = bool((result.get("breach") or {}).get("pwned"))
        ok = hope_ok(case["hope"], label, aborted)
        if not ok:
            mismatches += 1
        print(
            f"{'OK' if ok else '??'} {case['id']:30} {str(label):12} "
            f"{'Y' if pwned else 'n':5} {case['hope']:8} "
            f"occ={count if count is not None else '-'} reasons={result.get('reasons')}"
        )
        e2e = to_e2e_case(case, result)
        by_id[e2e["id"]] = e2e
        scored_rows.append(
            {
                **case,
                "label": label,
                "pwned": pwned,
                "occurrences": (result.get("breach") or {}).get("occurrences"),
                "strength_bits": result.get("strength_bits"),
                "keyspace_bits": result.get("keyspace_bits"),
                "reasons": result.get("reasons"),
                "hope_met": ok,
            }
        )

    existing["description"] = (
        "Handcrafted tricky cases: novel strong, leet/keyboard/year/pop-culture traps, "
        "structured constants, multilingual."
    )
    # stable order: previous ids first, then new
    old_ids = [c["id"] for c in existing.get("cases", [])]
    ordered = []
    seen = set()
    for i in old_ids + [c["id"] for c in NEW_CASES]:
        if i in by_id and i not in seen:
            ordered.append(by_id[i])
            seen.add(i)
    existing["cases"] = ordered
    corpus_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    out = ROOT / "e2e" / "results" / "tricky_expand.json"
    out.write_text(json.dumps({"cases": scored_rows}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("-" * 80)
    print(f"corpus cases now: {len(ordered)}; hope mismatches on NEW only: {mismatches}")
    print(f"wrote {corpus_path} and {out}")


if __name__ == "__main__":
    main()
