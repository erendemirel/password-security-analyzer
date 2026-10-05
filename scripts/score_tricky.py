#!/usr/bin/env python3
"""Score a handcrafted tricky suite and print a compact report."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PSA = ROOT / "target" / "release" / "psa.exe"
if not PSA.exists():
    PSA = ROOT / "target" / "release" / "psa"

# intent: what we *hope* the meter does (advisory sanity check)
CASES = [
    # --- should look strong ---
    {
        "id": "novel_random_16",
        "password": "kR7!mQx#9vLp$2nW",
        "intent": "novel random → very_strong / strong",
        "hope": "strong+",
    },
    {
        "id": "novel_passphrase_uncommon",
        "password": "orchid-waltz-mercury-lantern-84!",
        "intent": "unpublished diceware-ish phrase → strong+",
        "hope": "strong+",
    },
    {
        "id": "long_random_24",
        "password": "bN4$wE8*qT1!zY6@uI3#oP9",
        "intent": "long random → very_strong",
        "hope": "very_strong",
    },
    # --- tricky weak / fair ---
    {
        "id": "leet_password",
        "password": "P@ssw0rd!",
        "intent": "classic leet of password → weak (HIBP or known)",
        "hope": "weak",
    },
    {
        "id": "keyboard_walk",
        "password": "qwertyuiopasdfgh",
        "intent": "keyboard row walk → weak",
        "hope": "weak",
    },
    {
        "id": "year_suffix_common",
        "password": "Welcome2024!",
        "intent": "common word + year + bang → weak/fair",
        "hope": "weak-fair",
    },
    {
        "id": "almost_alphabet",
        "password": "abcdefghijklmno",
        "intent": "15-char alpha run → sequential demotion weak",
        "hope": "weak",
    },
    {
        "id": "reversed_digits",
        "password": "987654321",
        "intent": "reverse digit run → weak",
        "hope": "weak",
    },
    {
        "id": "repeat_block",
        "password": "abcabcabcabc",
        "intent": "repeated block — may not hit sequential; expect not very_strong",
        "hope": "not_very_strong",
    },
    {
        "id": "spaces_phrase_common",
        "password": "i love you",
        "intent": "spaced common phrase → weak if known/pwned",
        "hope": "weak-fair",
    },
    {
        "id": "camel_common",
        "password": "ILoveYou123",
        "intent": "camel + digits of iloveyou → weak/fair",
        "hope": "weak-fair",
    },
    {
        "id": "short_complex",
        "password": "A1!b",
        "intent": "short mixed charset — still weak by length/guesses",
        "hope": "weak",
    },
    {
        "id": "all_symbols_short",
        "password": "!@#$%^&*",
        "intent": "symbol run — often pwned / patterned → weak",
        "hope": "weak",
    },
    {
        "id": "uuid_looking",
        "password": "550e8400-e29b-41d4-a716-446655440000",
        "intent": "UUID shape → weak via structured_uuid demotion",
        "hope": "weak",
    },
    {
        "id": "base64ish_padding",
        "password": "cGFzc3dvcmQ=",
        "intent": "base64('password') — tricky; hope not very_strong",
        "hope": "not_very_strong",
    },
    {
        "id": "german_novel_phrase",
        "password": "nebelwald-klangfarbe-7x!",
        "intent": "German-ish novel compound → hopefully strong (not in lists)",
        "hope": "strong+",
    },
    {
        "id": "insert_digits_mid",
        "password": "pass4word",
        "intent": "common with mid digit → weak",
        "hope": "weak",
    },
    {
        "id": "double_word",
        "password": "passwordpassword",
        "intent": "doubled common → weak",
        "hope": "weak",
    },
]


def run(pw: str, hibp: bool) -> dict:
    cmd = [str(PSA), "analyze-offline", pw]
    hibp_path = ROOT / "data" / "hibp" / "ranges"
    if hibp and hibp_path.exists():
        cmd += ["--hibp-offline", str(hibp_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr or proc.stdout}
    r = json.loads(proc.stdout)
    r["ok"] = True
    return r


def hope_ok(hope: str, label: str | None, aborted: bool) -> bool:
    rank = {"weak": 0, "fair": 1, "strong": 2, "very_strong": 3, None: -1}
    r = rank.get(label, -1)
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


def main() -> int:
    if not PSA.exists():
        print("build psa first", file=sys.stderr)
        return 2

    rows = []
    bad = 0
    print(f"{'id':28} {'label':12} {'bits':7} {'hibp':5} reasons")
    print("-" * 90)
    for case in CASES:
        r = run(case["password"], hibp=True)
        if not r.get("ok"):
            print(f"{case['id']:28} ERROR {r.get('error')}")
            bad += 1
            continue
        label = r.get("label")
        bits = r.get("strength_bits")
        aborted = bool(r.get("aborted"))
        breach = r.get("breach") or {}
        reasons = ",".join(r.get("reasons") or [])
        ok = hope_ok(case["hope"], label, aborted)
        if not ok:
            bad += 1
        mark = "OK " if ok else "???"
        bits_s = f"{bits:.1f}" if isinstance(bits, (int, float)) else "-"
        hibp = "Y" if breach.get("pwned") else "n"
        print(f"{mark} {case['id']:26} {str(label):12} {bits_s:7} {hibp:5} {reasons}")
        rows.append(
            {
                **case,
                "label": label,
                "strength_bits": bits,
                "guess_number": r.get("guess_number"),
                "keyspace_bits": r.get("keyspace_bits"),
                "aborted": aborted,
                "pwned": breach.get("pwned"),
                "occurrences": breach.get("occurrences"),
                "reasons": r.get("reasons"),
                "hope_met": ok,
            }
        )

    out = ROOT / "e2e" / "results" / "tricky_manual.json"
    out.write_text(json.dumps({"cases": rows}, indent=2) + "\n", encoding="utf-8")
    print("-" * 90)
    print(f"hope matched {len(rows) - bad}/{len(rows)}; wrote {out}")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
