#!/usr/bin/env python3
"""End-to-end tests: invoke real `psa` CLI, assert labels, archive results for trends.

Usage:
  python e2e/run_e2e.py
  python e2e/run_e2e.py --psa target/release/psa.exe
  python e2e/run_e2e.py --update-baseline

Results land in e2e/results/<timestamp>.json and e2e/results/latest.json.
Regressions vs e2e/results/baseline.json fail the run (label stronger than before
on cases that previously met expectations, or expectation failures).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = Path(__file__).resolve().parent / "results"
CORPUS = Path(__file__).resolve().parent / "corpus.json"
CORPUS_SECLISTS = Path(__file__).resolve().parent / "corpus_seclists.json"
CORPUS_HIBP = Path(__file__).resolve().parent / "corpus_hibp.json"
CORPUS_TRICKY = Path(__file__).resolve().parent / "corpus_tricky.json"
CORPUS_KEYSPACE = Path(__file__).resolve().parent / "corpus_keyspace.json"
HIBP_OFFLINE = ROOT / "data" / "hibp" / "ranges"

LABEL_RANK = {
    None: -1,
    "weak": 0,
    "fair": 1,
    "strong": 2,
    "very_strong": 3,
}


def _corpus_rel(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def load_cases(paths: list[Path]) -> tuple[list[dict], list[str]]:
    cases: list[dict] = []
    refs: list[str] = []
    seen_ids: set[str] = set()
    for path in paths:
        path = path if path.is_absolute() else (ROOT / path)
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("reference"):
            refs.append(data["reference"])
        if data.get("source"):
            refs.append(data["source"])
        for case in data.get("cases", []):
            cid = case["id"]
            if cid in seen_ids:
                raise SystemExit(f"duplicate case id: {cid} in {path}")
            seen_ids.add(cid)
            cases.append(case)
    return cases, refs


def find_psa(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            raise SystemExit(f"psa binary not found: {p}")
        return p
    candidates = [
        ROOT / "target" / "release" / "psa.exe",
        ROOT / "target" / "release" / "psa",
        ROOT / "target" / "debug" / "psa.exe",
        ROOT / "target" / "debug" / "psa",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise SystemExit(
        "psa binary not found; build with:\n"
        "  cargo +stable-x86_64-pc-windows-gnu build -p psa-cli --release"
    )


def run_psa(psa: Path, password: str, mode: str, hibp_offline: Path | None) -> dict:
    if mode == "offline_no_model":
        cmd = [str(psa), "analyze-offline", password, "--no-model"]
    elif mode == "offline_hibp":
        if hibp_offline is None or not hibp_offline.exists():
            return {
                "ok": False,
                "error": "hibp offline store missing; run: python scripts/download_hibp.py --e2e",
            }
        cmd = [
            str(psa),
            "analyze-offline",
            password,
            "--hibp-offline",
            str(hibp_offline),
        ]
    else:
        cmd = [str(psa), "analyze-offline", password]
    # Empty password: clap needs an argument — pass empty string explicitly
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}",
            "stdout": proc.stdout,
        }
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"invalid JSON: {e}", "stdout": proc.stdout}
    data["ok"] = True
    return data


def check_expect(result: dict, expect: dict) -> list[str]:
    failures = []
    if not result.get("ok"):
        failures.append(f"cli_error: {result.get('error')}")
        return failures

    label = result.get("label")
    rank = LABEL_RANK.get(label, -1)

    if expect.get("label_null"):
        if label is not None:
            failures.append(f"expected null label, got {label}")
    if "max_label" in expect:
        max_r = LABEL_RANK[expect["max_label"]]
        if rank > max_r:
            failures.append(f"label {label} stronger than max {expect['max_label']}")
    if "min_label" in expect:
        min_r = LABEL_RANK[expect["min_label"]]
        if rank < min_r:
            failures.append(f"label {label} weaker than min {expect['min_label']}")
    if "min_keyspace_bits" in expect:
        bits = float(result.get("keyspace_bits") or 0)
        if bits + 1e-9 < expect["min_keyspace_bits"]:
            failures.append(f"keyspace_bits {bits} < {expect['min_keyspace_bits']}")
    if "reasons_any" in expect:
        reasons = result.get("reasons") or []
        if not any(r in reasons for r in expect["reasons_any"]):
            failures.append(f"missing any of reasons {expect['reasons_any']}; got {reasons}")
    if "aborted" in expect:
        if bool(result.get("aborted")) != bool(expect["aborted"]):
            failures.append(f"aborted={result.get('aborted')} expected {expect['aborted']}")
    if "pwned" in expect:
        breach = result.get("breach") or {}
        if bool(breach.get("pwned")) != bool(expect["pwned"]):
            failures.append(f"pwned={breach.get('pwned')} expected {expect['pwned']}")
    if "breach_source" in expect:
        breach = result.get("breach") or {}
        if breach.get("source") != expect["breach_source"]:
            failures.append(
                f"breach.source={breach.get('source')} expected {expect['breach_source']}"
            )
    if expect.get("strength_bits_le_keyspace"):
        sb = result.get("strength_bits")
        kb = result.get("keyspace_bits")
        if sb is None or kb is None:
            failures.append(
                f"strength_bits_le_keyspace requires both fields; got strength_bits={sb} keyspace_bits={kb}"
            )
        elif float(sb) > float(kb) + 1e-6:
            failures.append(
                f"strength_bits {sb} exceeds keyspace_bits {kb} (Markov overrate without keyspace cap)"
            )
    if "max_strength_bits" in expect:
        sb = result.get("strength_bits")
        if sb is None:
            failures.append("max_strength_bits set but strength_bits missing")
        elif float(sb) > float(expect["max_strength_bits"]) + 1e-6:
            failures.append(
                f"strength_bits {sb} > max_strength_bits {expect['max_strength_bits']}"
            )
    return failures


def check_global_invariants(result: dict) -> list[str]:
    """Always-on guards for scored (non-aborted model) results."""
    failures = []
    if not result.get("ok"):
        return failures
    # Breach-abort path may omit model scores; only check when both are present.
    sb = result.get("strength_bits")
    kb = result.get("keyspace_bits")
    if sb is not None and kb is not None:
        if float(sb) > float(kb) + 1e-6:
            failures.append(
                f"invariant: strength_bits {sb} > keyspace_bits {kb}"
            )
    return failures


def compare_trend(current_cases: list[dict], baseline: dict | None) -> list[str]:
    """Fail if a case that passed before now has a stronger label (unsafe regression)."""
    if not baseline:
        return []
    prev = {c["id"]: c for c in baseline.get("cases", [])}
    regs = []
    for c in current_cases:
        p = prev.get(c["id"])
        if not p or not p.get("passed"):
            continue
        old_l = p.get("label")
        new_l = c.get("label")
        if LABEL_RANK.get(new_l, -1) > LABEL_RANK.get(old_l, -1):
            # Stronger label than last good baseline = possible unsafe regression
            if c.get("passed"):
                regs.append(
                    f"trend_stronger_label {c['id']}: {old_l} -> {new_l}"
                )
        if p.get("passed") and not c.get("passed"):
            regs.append(f"trend_now_failing {c['id']}: {c.get('failures')}")
    return regs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--psa", help="Path to psa binary")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument(
        "--corpus",
        type=Path,
        action="append",
        default=None,
        help="Corpus JSON (repeatable). Default: corpus.json + corpus_seclists.json if present",
    )
    args = ap.parse_args()

    psa = find_psa(args.psa)
    corpus_paths = args.corpus or [
        CORPUS,
        CORPUS_SECLISTS,
        CORPUS_HIBP,
        CORPUS_TRICKY,
        CORPUS_KEYSPACE,
    ]
    cases, refs = load_cases(corpus_paths)
    if not cases:
        raise SystemExit(f"no cases loaded from {corpus_paths}")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    hibp_offline = HIBP_OFFLINE if HIBP_OFFLINE.exists() else None

    case_results = []
    n_fail = 0
    for case in cases:
        mode = case.get("mode", "offline")
        if mode == "offline_hibp" and hibp_offline is None:
            n_fail += 1
            case_results.append(
                {
                    "id": case["id"],
                    "password": case["password"],
                    "tags": case.get("tags", []),
                    "mode": mode,
                    "passed": False,
                    "failures": [
                        "hibp offline store missing; run: python scripts/download_hibp.py --e2e"
                    ],
                    "label": None,
                    "guess_number": None,
                    "strength_bits": None,
                    "keyspace_bits": None,
                    "reasons": None,
                    "aborted": None,
                    "error": "missing hibp offline store",
                }
            )
            continue
        raw = run_psa(psa, case["password"], mode, hibp_offline)
        failures = check_expect(raw, case.get("expect", {}))
        failures.extend(check_global_invariants(raw))
        passed = not failures
        if not passed:
            n_fail += 1
        case_results.append(
            {
                "id": case["id"],
                "password": case["password"],
                "tags": case.get("tags", []),
                "mode": mode,
                "passed": passed,
                "failures": failures,
                "label": raw.get("label"),
                "guess_number": raw.get("guess_number"),
                "strength_bits": raw.get("strength_bits"),
                "keyspace_bits": raw.get("keyspace_bits"),
                "reasons": raw.get("reasons"),
                "aborted": raw.get("aborted"),
                "breach": raw.get("breach"),
                "error": raw.get("error"),
            }
        )

    baseline_path = RESULTS / "baseline.json"
    baseline = None
    if baseline_path.exists():
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

    trend_issues = compare_trend(case_results, baseline)
    n_fail += len(trend_issues)

    summary = {
        "timestamp_utc": ts,
        "psa_binary": str(psa),
        "corpora": [_corpus_rel(p) for p in corpus_paths if p.exists()],
        "references": refs,
        "total": len(case_results),
        "passed": sum(1 for c in case_results if c["passed"]),
        "failed": sum(1 for c in case_results if not c["passed"]),
        "trend_regressions": trend_issues,
        "label_histogram": {},
        "cases": case_results,
    }
    hist: dict[str, int] = {}
    for c in case_results:
        key = c["label"] if c["label"] is not None else "null"
        hist[key] = hist.get(key, 0) + 1
    summary["label_histogram"] = hist

    RESULTS.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS / f"{ts}.json"
    latest_path = RESULTS / "latest.json"
    text = json.dumps(summary, indent=2)
    out_path.write_text(text, encoding="utf-8")
    latest_path.write_text(text, encoding="utf-8")

    if args.update_baseline and summary["failed"] == 0 and not trend_issues:
        baseline_path.write_text(text, encoding="utf-8")
        print(f"Updated baseline -> {baseline_path}")

    print(f"psa: {psa}")
    print(f"corpora: {summary['corpora']}")
    print(f"passed {summary['passed']}/{summary['total']}")
    print(f"histogram: {hist}")
    print(f"wrote {out_path}")
    if trend_issues:
        print("TREND REGRESSIONS:")
        for t in trend_issues:
            print(f"  - {t}")
    if n_fail:
        print("FAILURES:")
        for c in case_results:
            if not c["passed"]:
                print(f"  - {c['id']}: {c['failures']} (label={c['label']})")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
