#!/usr/bin/env python3
"""Leak-corpus evaluation: Type 2 histograms + optional zxcvbn + 1a Spearman.

Manual / nightly (not a hard e2e gate). Measures:
  - Type 2: RockYou head vs random / passphrase controls (label buckets)
  - zxcvbn: same RockYou sample side-by-side (opt-in --with-zxcvbn)
  - 1a: Spearman(log guess_number, log freq_rank) on ranks > holdout-min-rank

1a caveat: frequency popularity is not Hashcat/PGS attack order.

Usage:
  python scripts/eval_leak.py
  python scripts/eval_leak.py --limit 10000 --controls 200
  python scripts/eval_leak.py --with-zxcvbn
"""

from __future__ import annotations

import argparse
import json
import math
import random
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROCKYOU = ROOT / "data" / "seclists" / "rockyou.txt"
DEFAULT_OUT = ROOT / "e2e" / "results"

# Small embedded list for Diceware-ish controls (not a security boundary).
PASSPHRASE_WORDS = [
    "orchid", "waltz", "mercury", "lantern", "cedar", "pebble", "horizon",
    "velvet", "comet", "meadow", "cinder", "harbor", "quartz", "willow",
    "ember", "glacier", "nectar", "ripple", "saffron", "timber", "amber",
    "blossom", "canyon", "drizzle", "echo", "falcon", "grove", "hazel",
    "ivory", "jasper", "kelp", "lotus", "maple", "nickel", "olive",
    "petal", "quill", "raven", "spruce", "tulip", "umbra", "violet",
    "walnut", "xenon", "yarrow", "zephyr", "anchor", "breeze", "coral",
    "delta", "eagle", "fjord", "ginger", "honey", "island", "jade",
]

RANDOM_CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!@#$%"
)

PSA_LABELS = ("weak", "fair", "strong", "very_strong")


def find_psa(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            raise SystemExit(f"psa binary not found: {p}")
        return p
    for c in (
        ROOT / "target" / "release" / "psa.exe",
        ROOT / "target" / "release" / "psa",
        ROOT / "target" / "debug" / "psa.exe",
        ROOT / "target" / "debug" / "psa",
    ):
        if c.exists():
            return c
    raise SystemExit(
        "psa binary not found; build with:\n"
        "  cargo +stable-x86_64-pc-windows-gnu build -p psa-cli --release"
    )


def score_batch(psa: Path, passwords: list[str]) -> list[dict]:
    if not passwords:
        return []
    proc = subprocess.run(
        [str(psa), "analyze-offline", "--batch"],
        input="\n".join(passwords) + "\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"psa --batch failed ({proc.returncode}): {proc.stderr or proc.stdout}"
        )
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if len(lines) != len(passwords):
        raise SystemExit(
            f"psa --batch returned {len(lines)} lines for {len(passwords)} passwords"
        )
    return [json.loads(ln) for ln in lines]


def read_rockyou_head(path: Path, limit: int) -> list[tuple[int, str]]:
    """Return (1-based rank, password) for the first `limit` non-empty lines."""
    out: list[tuple[int, str]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for rank, line in enumerate(fh, start=1):
            pw = line.rstrip("\r\n")
            if not pw:
                continue
            out.append((rank, pw))
            if len(out) >= limit:
                break
    return out


def read_rockyou_holdout(
    path: Path, holdout_min_rank: int, limit: int
) -> list[tuple[int, str]]:
    """Stratified sample of up to `limit` passwords with rank > holdout_min_rank.

    Contiguous bands (e.g. 500001..550000) have nearly flat popularity, so
    Spearman vs line-rank is noise. Walk the whole tail with a fixed stride.
    """
    # Pass 1: count eligible lines
    eligible = 0
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for rank, line in enumerate(fh, start=1):
            if rank <= holdout_min_rank:
                continue
            if line.rstrip("\r\n"):
                eligible += 1
    if eligible == 0:
        return []
    step = max(1, eligible // limit) if limit > 0 else 1

    out: list[tuple[int, str]] = []
    seen = 0
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for rank, line in enumerate(fh, start=1):
            if rank <= holdout_min_rank:
                continue
            pw = line.rstrip("\r\n")
            if not pw:
                continue
            if seen % step == 0:
                out.append((rank, pw))
                if len(out) >= limit:
                    break
            seen += 1
    return out


def gen_random(n: int, rng: random.Random, length: int = 16) -> list[str]:
    return ["".join(rng.choice(RANDOM_CHARSET) for _ in range(length)) for _ in range(n)]


def gen_passphrases(n: int, rng: random.Random) -> list[str]:
    out: list[str] = []
    for _ in range(n):
        words = [rng.choice(PASSPHRASE_WORDS) for _ in range(4)]
        out.append(f"{'-'.join(words)}-{rng.randint(10, 99)}")
    return out


def empty_psa_hist() -> dict[str, int]:
    return {lab: 0 for lab in PSA_LABELS}


def summarize_psa(results: list[dict]) -> dict:
    hist = empty_psa_hist()
    null_n = 0
    for r in results:
        lab = r.get("label")
        if lab is None:
            null_n += 1
        elif lab in hist:
            hist[lab] += 1
        else:
            hist[lab] = hist.get(lab, 0) + 1
    n = len(results)
    weak_fair = hist.get("weak", 0) + hist.get("fair", 0)
    strong_plus = hist.get("strong", 0) + hist.get("very_strong", 0)
    return {
        "n": n,
        "histogram": hist,
        "null_label": null_n,
        "pct_weak_or_fair": round(100.0 * weak_fair / n, 2) if n else 0.0,
        "pct_strong_plus": round(100.0 * strong_plus / n, 2) if n else 0.0,
    }


def summarize_zxcvbn(scores: list[int]) -> dict:
    hist = {str(i): 0 for i in range(5)}
    for s in scores:
        key = str(max(0, min(4, int(s))))
        hist[key] += 1
    n = len(scores)
    weakish = hist["0"] + hist["1"]
    strongish = hist["3"] + hist["4"]
    return {
        "n": n,
        "histogram": hist,
        "pct_0_or_1": round(100.0 * weakish / n, 2) if n else 0.0,
        "pct_3_or_4": round(100.0 * strongish / n, 2) if n else 0.0,
        "note": "zxcvbn score 0-1 ≈ weak-ish; 3-4 ≈ strong-ish",
    }


def _rankdata(vals: list[float]) -> list[float]:
    """Average ranks for ties (1-based)."""
    indexed = sorted(enumerate(vals), key=lambda t: t[1])
    ranks = [0.0] * len(vals)
    i = 0
    while i < len(indexed):
        j = i
        while j + 1 < len(indexed) and indexed[j + 1][1] == indexed[i][1]:
            j += 1
        # ranks i..j (0-based position) -> average of (i+1)..(j+1)
        avg = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            ranks[indexed[k][0]] = avg
        i = j + 1
    return ranks


def pearson(xs: list[float], ys: list[float]) -> float | None:
    n = len(xs)
    if n < 2:
        return None
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    dy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if dx == 0.0 or dy == 0.0:
        return None
    return num / (dx * dy)


def spearman(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    return pearson(_rankdata(xs), _rankdata(ys))


def print_psa_table(name: str, summary: dict) -> None:
    h = summary["histogram"]
    print(
        f"  {name:12} n={summary['n']:<6} "
        f"weak={h.get('weak', 0):<6} fair={h.get('fair', 0):<6} "
        f"strong={h.get('strong', 0):<6} very_strong={h.get('very_strong', 0):<6} "
        f"| weak|fair={summary['pct_weak_or_fair']}%  strong+={summary['pct_strong_plus']}%"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=50_000, help="RockYou sample size")
    ap.add_argument(
        "--controls", type=int, default=1_000, help="Random and passphrase count each"
    )
    ap.add_argument(
        "--holdout-min-rank",
        type=int,
        default=500_000,
        help="1a only on RockYou ranks > this (beyond known.bin head)",
    )
    ap.add_argument("--with-zxcvbn", action="store_true")
    ap.add_argument("--psa", type=str, default=None)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--rockyou", type=Path, default=ROCKYOU)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    if not args.rockyou.exists():
        raise SystemExit(
            f"RockYou missing: {args.rockyou}\n"
            "  python scripts/download_seclists.py --rockyou"
        )

    psa = find_psa(args.psa)
    rng = random.Random(args.seed)

    print(f"psa: {psa}")
    print(f"rockyou: {args.rockyou}")
    print(f"limit={args.limit} controls={args.controls} holdout_min_rank={args.holdout_min_rank}")

    # --- Type 2: RockYou head ---
    print("reading RockYou head...")
    head = read_rockyou_head(args.rockyou, args.limit)
    if not head:
        raise SystemExit("RockYou head empty")
    print(f"scoring RockYou head ({len(head)})...")
    head_results = score_batch(psa, [pw for _, pw in head])
    rockyou_summary = summarize_psa(head_results)

    # --- Controls ---
    print(f"scoring controls (random={args.controls}, passphrase={args.controls})...")
    random_pws = gen_random(args.controls, rng)
    phrase_pws = gen_passphrases(args.controls, rng)
    random_summary = summarize_psa(score_batch(psa, random_pws))
    phrase_summary = summarize_psa(score_batch(psa, phrase_pws))

    # --- 1a holdout ---
    print("reading RockYou holdout for 1a...")
    holdout = read_rockyou_holdout(args.rockyou, args.holdout_min_rank, args.limit)
    holdout_note = None
    if len(holdout) < args.limit:
        holdout_note = (
            f"only {len(holdout)} passwords with rank > {args.holdout_min_rank} "
            f"(requested {args.limit})"
        )
        print(f"  note: {holdout_note}")

    spearman_rho = None
    holdout_n = 0
    if holdout:
        print(f"scoring holdout ({len(holdout)})...")
        holdout_results = score_batch(psa, [pw for _, pw in holdout])
        xs: list[float] = []
        ys: list[float] = []
        for (rank, _), r in zip(holdout, holdout_results):
            gn = r.get("guess_number")
            if gn is None or gn <= 0 or rank <= 0:
                continue
            xs.append(math.log(float(gn)))
            ys.append(math.log(float(rank)))
        holdout_n = len(xs)
        spearman_rho = spearman(xs, ys)
    else:
        holdout_note = (
            holdout_note
            or f"no passwords with rank > {args.holdout_min_rank}; skip 1a"
        )

    # --- Optional zxcvbn ---
    zxcvbn_block = None
    if args.with_zxcvbn:
        try:
            from zxcvbn import zxcvbn  # type: ignore
        except ImportError:
            raise SystemExit(
                "--with-zxcvbn requires the zxcvbn package:\n"
                "  pip install zxcvbn"
            )
        print(f"scoring RockYou head with zxcvbn ({len(head)})...")
        z_scores = [zxcvbn(pw)["score"] for _, pw in head]
        zxcvbn_block = {
            "rockyou": summarize_zxcvbn(z_scores),
        }

    report = {
        "meta": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "psa": str(psa),
            "rockyou": str(args.rockyou),
            "model_mode": "embedded (analyze-offline, no HIBP)",
            "limit": args.limit,
            "controls": args.controls,
            "holdout_min_rank": args.holdout_min_rank,
            "seed": args.seed,
            "with_zxcvbn": args.with_zxcvbn,
        },
        "type2": {
            "rockyou": rockyou_summary,
            "random": random_summary,
            "passphrase": phrase_summary,
        },
        "1a": {
            "n": holdout_n,
            "spearman_log_guess_vs_log_rank": (
                round(spearman_rho, 4) if spearman_rho is not None else None
            ),
            "holdout_min_rank": args.holdout_min_rank,
            "note": "popularity (freq rank), not attack order (Hashcat/PGS)",
            "sampling_note": holdout_note,
        },
    }
    if zxcvbn_block is not None:
        report["zxcvbn"] = zxcvbn_block

    print()
    print("Type 2 — PSA label histograms")
    print_psa_table("rockyou", rockyou_summary)
    print_psa_table("random", random_summary)
    print_psa_table("passphrase", phrase_summary)
    if zxcvbn_block:
        zh = zxcvbn_block["rockyou"]["histogram"]
        print()
        print("zxcvbn — RockYou score histogram (0=weak .. 4=strong)")
        print(
            f"  rockyou     n={zxcvbn_block['rockyou']['n']:<6} "
            + " ".join(f"{k}={zh[k]}" for k in sorted(zh, key=int))
            + f"  | 0|1={zxcvbn_block['rockyou']['pct_0_or_1']}%  "
            f"3|4={zxcvbn_block['rockyou']['pct_3_or_4']}%"
        )
    print()
    rho_s = (
        f"{spearman_rho:.4f}" if spearman_rho is not None else "n/a"
    )
    print(f"1a — Spearman(log guess, log rank) n={holdout_n}  rho={rho_s}")
    print("     (popularity correlation; not PGS/Hashcat gold standard)")

    args.out.mkdir(parents=True, exist_ok=True)
    ts = report["meta"]["timestamp"]
    out_path = args.out / f"eval_{ts}.json"
    latest = args.out / "eval_latest.json"
    text = json.dumps(report, indent=2) + "\n"
    out_path.write_text(text, encoding="utf-8")
    latest.write_text(text, encoding="utf-8")
    print()
    print(f"wrote {out_path}")
    print(f"wrote {latest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
