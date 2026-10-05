#!/usr/bin/env python3
"""Download curated SecLists password files for training + e2e sampling.

Source: https://github.com/danielmiessler/SecLists/tree/master/Passwords
Files are fetched over HTTPS from raw.githubusercontent.com (not committed).

RockYou (optional, large): Passwords/Leaked-Databases/rockyou.txt.tar.gz
— the classic research / Edge-article corpus (~14M lines, frequency-sorted).
"""

from __future__ import annotations

import argparse
import io
import json
import random
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "seclists"
UA = "password-security-analyzer/0.1 (SecLists fetch; +https://github.com/danielmiessler/SecLists)"

# Prefer compact, high-signal lists (skip multi‑MB dumps by default).
CURATED = [
    "Common-Credentials/10k-most-common.txt",
    "Common-Credentials/100k-most-used-passwords-NCSC.txt",
    "Common-Credentials/Pwdb_top-10000.txt",
    "Common-Credentials/xato-net-10-million-passwords-10000.txt",
    "corporate_passwords.txt",
    "days.txt",
    "months.txt",
    "seasons.txt",
    "Most-Popular-Letter-Passes.txt",
]
# Optional larger lists (enable with --include-large)
LARGE = [
    "darkc0de.txt",
]

ROCKYOU_TAR = "Leaked-Databases/rockyou.txt.tar.gz"

RAW_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/"


def fetch(url: str, timeout: int = 600) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def list_common_credentials() -> list[str]:
    """Discover available files under Common-Credentials via GitHub API."""
    api = "https://api.github.com/repos/danielmiessler/SecLists/contents/Passwords/Common-Credentials"
    try:
        data = json.loads(fetch(api, timeout=120).decode("utf-8"))
    except Exception:
        return []
    return [
        f"Common-Credentials/{i['name']}"
        for i in data
        if i.get("type") == "file" and i["name"].endswith(".txt")
    ]


def download_one(rel: str, out_dir: Path) -> Path | None:
    url = RAW_BASE + rel.replace("\\", "/")
    dest = out_dir / Path(rel).name
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        body = fetch(url, timeout=120)
    except urllib.error.HTTPError as e:
        print(f"SKIP {rel} ({e.code})")
        return None
    except Exception as e:
        print(f"SKIP {rel} ({e})")
        return None
    dest.write_bytes(body)
    lines = sum(1 for _ in dest.open("rb"))
    print(f"OK   {rel} -> {dest.name} ({lines} lines, {len(body)} bytes)")
    return dest


def download_rockyou(out_dir: Path) -> Path | None:
    """Download and extract rockyou.txt from SecLists (tar.gz)."""
    dest_txt = out_dir / "rockyou.txt"
    if dest_txt.exists() and dest_txt.stat().st_size > 1_000_000:
        lines = sum(1 for _ in dest_txt.open("rb"))
        print(f"OK   rockyou.txt (cached, {lines} lines, {dest_txt.stat().st_size} bytes)")
        return dest_txt

    url = RAW_BASE + ROCKYOU_TAR
    print(f"Downloading RockYou archive (~53MB): {url}")
    try:
        body = fetch(url, timeout=1800)
    except Exception as e:
        print(f"SKIP RockYou ({e})")
        return None

    tar_path = out_dir / "rockyou.txt.tar.gz"
    tar_path.write_bytes(body)
    print(f"OK   saved {tar_path.name} ({len(body)} bytes); extracting…")

    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tf:
            member = None
            for m in tf.getmembers():
                name = Path(m.name).name.lower()
                if name == "rockyou.txt" or name.endswith("rockyou.txt"):
                    member = m
                    break
            if member is None:
                # fall back to first regular file
                for m in tf.getmembers():
                    if m.isfile():
                        member = m
                        break
            if member is None:
                print("SKIP RockYou (empty archive)")
                return None
            extracted = tf.extractfile(member)
            if extracted is None:
                print("SKIP RockYou (cannot extract member)")
                return None
            dest_txt.write_bytes(extracted.read())
    except Exception as e:
        print(f"SKIP RockYou extract ({e})")
        return None

    lines = sum(1 for _ in dest_txt.open("rb"))
    print(f"OK   rockyou.txt ({lines} lines, {dest_txt.stat().st_size} bytes)")
    return dest_txt


def is_wordlist_comment(pw: str) -> bool:
    """True for editor-style comments (`# note`), not passwords like `#1bitch`."""
    if not pw.startswith("#"):
        return False
    return len(pw) == 1 or pw[1].isspace()


def merge_wordlists(paths: list[Path], out: Path, max_lines: int | None) -> int:
    seen: set[str] = set()
    ordered: list[str] = []
    for p in paths:
        print(f"  merging {p.name}…")
        with p.open("r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                # Keep leading/trailing spaces that appear in real leaks; only
                # strip the newline. Skip blank lines and `# comment` headers.
                pw = raw.rstrip("\r\n")
                if not pw or is_wordlist_comment(pw) or pw in seen:
                    continue
                if len(pw) > 128:
                    continue
                seen.add(pw)
                ordered.append(pw)
                if max_lines and len(ordered) >= max_lines:
                    break
        if max_lines and len(ordered) >= max_lines:
            break
    out.write_text("\n".join(ordered) + "\n", encoding="utf-8")
    return len(ordered)


def sample_for_e2e(
    merged: Path,
    common_path: Path | None,
    corpus_extra: Path,
    n: int,
    seed: int,
) -> int:
    """Sample e2e cases primarily from top-common list (expect weak)."""
    rng = random.Random(seed)
    if common_path and common_path.exists():
        lines = [
            ln.strip()
            for ln in common_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if ln.strip() and 4 <= len(ln.strip()) <= 32
        ]
        max_label = "weak"
        tag = "seclists-common"
    else:
        # Take from head of merged (most common if RockYou-first)
        lines = []
        with merged.open("r", encoding="utf-8", errors="ignore") as fh:
            for ln in fh:
                pw = ln.strip()
                if pw and 4 <= len(pw) <= 24:
                    lines.append(pw)
                if len(lines) >= 50_000:
                    break
        max_label = "fair"
        tag = "seclists-sampled"

    sample = rng.sample(lines, min(n, len(lines)))
    cases = []
    for i, pw in enumerate(sample):
        cases.append(
            {
                "id": f"seclists_{i:04d}",
                "password": pw,
                "tags": ["seclists", tag],
                "expect": {"max_label": max_label},
            }
        )

    corpus_extra.write_text(
        json.dumps(
            {
                "description": "Auto-sampled from SecLists Passwords (see scripts/download_seclists.py)",
                "source": "https://github.com/danielmiessler/SecLists/tree/master/Passwords",
                "cases": cases,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return len(cases)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument(
        "--max-train-lines",
        type=int,
        default=None,
        help="Cap unique training lines (default: 150k, or unlimited with --rockyou)",
    )
    ap.add_argument("--e2e-samples", type=int, default=150)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--discover", action="store_true", help="Also try listing Common-Credentials via API")
    ap.add_argument("--include-large", action="store_true", help="Also download large lists like darkc0de.txt")
    ap.add_argument(
        "--rockyou",
        action="store_true",
        help="Download + include RockYou (Leaked-Databases/rockyou.txt.tar.gz)",
    )
    args = ap.parse_args()

    if args.max_train_lines is None:
        args.max_train_lines = None if args.rockyou else 150_000

    args.out_dir.mkdir(parents=True, exist_ok=True)
    rels = list(CURATED)
    if args.include_large:
        rels.extend(LARGE)
    if args.discover:
        discovered = list_common_credentials()
        for d in discovered:
            if d not in rels:
                rels.append(d)

    downloaded: list[Path] = []
    for rel in rels:
        p = download_one(rel, args.out_dir)
        if p:
            downloaded.append(p)

    rockyou_path = None
    if args.rockyou:
        rockyou_path = download_rockyou(args.out_dir)
        # Append after curated lists so known.bin ranks common lists first;
        # RockYou still fills the bulk of Markov training.
        if rockyou_path:
            downloaded.append(rockyou_path)

    if not downloaded:
        raise SystemExit("No SecLists files downloaded")

    merged = args.out_dir / "merged_train.txt"
    n = merge_wordlists(downloaded, merged, args.max_train_lines)
    print(f"Merged {n} unique passwords -> {merged}")

    final = args.out_dir / "train_combined.txt"
    # Same content as merged (kept as the canonical train path for scripts/docs).
    final.write_bytes(merged.read_bytes())
    print(f"Train wordlist -> {final} ({n} lines)")

    e2e_frag = ROOT / "e2e" / "corpus_seclists.json"
    common = args.out_dir / "10k-most-common.txt"
    n_e2e = sample_for_e2e(
        merged, common if common.exists() else None, e2e_frag, args.e2e_samples, args.seed
    )
    print(f"Wrote {n_e2e} e2e samples -> {e2e_frag}")

    meta = {
        "source": "https://github.com/danielmiessler/SecLists/tree/master/Passwords",
        "files": [p.name for p in downloaded],
        "rockyou": bool(rockyou_path),
        "merged_unique": n,
        "combined_unique": n,
        "max_train_lines": args.max_train_lines,
        "e2e_samples": n_e2e,
    }
    (args.out_dir / "manifest.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print("Done. Next:")
    print(f"  python scripts/train_markov.py --wordlist {final} --out-dir models --known-limit 500000")
    print("  cargo build -p psa-cli --release")
    print("  python e2e/run_e2e.py --update-baseline")


if __name__ == "__main__":
    main()
