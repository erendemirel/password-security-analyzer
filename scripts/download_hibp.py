#!/usr/bin/env python3
"""Download Have I Been Pwned hash ranges for offline breach checks + e2e.

SHA-1 dumps contain **no plaintext** — they cannot train Markov. Use SecLists
for model training; use this store for offline HIBP lookups.

Official tool: https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader

Modes:
  --e2e   Fetch only the range prefixes needed by e2e/seed corpora (small, default).
  --full  Invoke `haveibeenpwned-downloader` for the complete SHA-1 corpus (tens of GB).

Examples:
  python scripts/download_hibp.py --e2e
  python scripts/download_hibp.py --full
  python scripts/download_hibp.py --full --parallelism 64
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "hibp" / "ranges"
UA = "password-security-analyzer/0.1 (HIBP offline prep; +https://haveibeenpwned.com/API/v3)"
RANGE_URL = "https://api.pwnedpasswords.com/range/"


def sha1_prefix(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()[:5]


def collect_passwords() -> list[str]:
    passwords: list[str] = []
    seen: set[str] = set()

    def add(pw: str) -> None:
        if pw and pw not in seen:
            seen.add(pw)
            passwords.append(pw)

    for corpus in (
        ROOT / "e2e" / "corpus.json",
        ROOT / "e2e" / "corpus_seclists.json",
        ROOT / "e2e" / "corpus_hibp.json",
        ROOT / "e2e" / "corpus_tricky.json",
    ):
        if not corpus.exists():
            continue
        data = json.loads(corpus.read_text(encoding="utf-8"))
        for case in data.get("cases", []):
            add(case.get("password", ""))

    # Always include well-known pwned samples for offline tests
    for pw in ("password", "123456", "qwerty", "iloveyou", "admin", "letmein"):
        add(pw)

    return passwords


def fetch_range(prefix: str, dest: Path) -> bool:
    url = RANGE_URL + prefix
    req = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        print(f"SKIP {prefix} ({e.code})")
        return False
    except Exception as e:
        print(f"SKIP {prefix} ({e})")
        return False
    dest.write_bytes(body)
    return True


def download_e2e_subset(out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    passwords = collect_passwords()
    prefixes = sorted({sha1_prefix(pw) for pw in passwords})
    ok = 0
    for i, prefix in enumerate(prefixes, 1):
        dest = out_dir / f"{prefix}.txt"
        if dest.exists() and dest.stat().st_size > 0:
            ok += 1
            continue
        if fetch_range(prefix, dest):
            ok += 1
            print(f"OK   {prefix} ({i}/{len(prefixes)})")
        else:
            print(f"FAIL {prefix}")
    meta = {
        "mode": "e2e_subset",
        "source": "https://api.pwnedpasswords.com/range/",
        "compatible_with": "https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader",
        "passwords_considered": len(passwords),
        "prefixes": len(prefixes),
        "downloaded_or_cached": ok,
        "out_dir": str(out_dir.relative_to(ROOT)).replace("\\", "/"),
    }
    (out_dir.parent / "manifest.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )
    write_corpus_hibp()
    return meta


def write_corpus_hibp() -> None:
    """E2E cases that must abort as pwned against the local range store."""
    cases = [
        {
            "id": "hibp_offline_password",
            "password": "password",
            "tags": ["hibp", "offline"],
            "mode": "offline_hibp",
            "expect": {
                "aborted": True,
                "pwned": True,
                "max_label": "weak",
                "reasons_any": ["pwned_password"],
                "breach_source": "hibp_offline",
            },
        },
        {
            "id": "hibp_offline_123456",
            "password": "123456",
            "tags": ["hibp", "offline"],
            "mode": "offline_hibp",
            "expect": {
                "aborted": True,
                "pwned": True,
                "max_label": "weak",
                "reasons_any": ["pwned_password"],
            },
        },
        {
            "id": "hibp_offline_qwerty",
            "password": "qwerty",
            "tags": ["hibp", "offline"],
            "mode": "offline_hibp",
            "expect": {
                "aborted": True,
                "pwned": True,
                "max_label": "weak",
                "reasons_any": ["pwned_password"],
            },
        },
        {
            "id": "hibp_offline_iloveyou",
            "password": "iloveyou",
            "tags": ["hibp", "offline", "edge-article"],
            "mode": "offline_hibp",
            "expect": {
                "aborted": True,
                "pwned": True,
                "max_label": "weak",
                "reasons_any": ["pwned_password"],
            },
        },
    ]
    path = ROOT / "e2e" / "corpus_hibp.json"
    path.write_text(
        json.dumps(
            {
                "description": "Offline HIBP e2e (PwnedPasswordsDownloader-compatible ranges in data/hibp/ranges)",
                "source": "https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader",
                "cases": cases,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {path.relative_to(ROOT)} ({len(cases)} cases)")


def find_downloader() -> str | None:
    for name in ("haveibeenpwned-downloader", "haveibeenpwned-downloader.exe"):
        path = shutil.which(name)
        if path:
            return path
    return None


def download_full(out_dir: Path, parallelism: int | None, force: bool) -> None:
    tool = find_downloader()
    if not tool:
        print(
            "haveibeenpwned-downloader not found on PATH.\n"
            "Install (.NET 10+):\n"
            "  dotnet tool install --global haveibeenpwned-downloader\n"
            "See https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader",
            file=sys.stderr,
        )
        raise SystemExit(2)

    out_dir.mkdir(parents=True, exist_ok=True)
    # Tool takes an output *name*; for directory mode the name is the directory path.
    cmd = [tool, str(out_dir)]
    if parallelism is not None:
        cmd.extend(["-p", str(parallelism)])
    if force:
        cmd.append("--force")
    print("Running:", " ".join(cmd))
    print("Note: full SHA-1 dump is tens of GB and can take a long time.")
    subprocess.check_call(cmd)
    meta = {
        "mode": "full",
        "tool": "haveibeenpwned-downloader",
        "source": "https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader",
        "out_dir": str(out_dir.relative_to(ROOT)).replace("\\", "/"),
    }
    (out_dir.parent / "manifest.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )
    write_corpus_hibp()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--e2e",
        action="store_true",
        help="Download only prefixes needed for local e2e/seed (default if neither flag)",
    )
    mode.add_argument(
        "--full",
        action="store_true",
        help="Run official haveibeenpwned-downloader for the complete SHA-1 set",
    )
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--parallelism", "-p", type=int, default=None)
    ap.add_argument("--force", action="store_true", help="Full mode: ignore ETag index")
    ap.add_argument(
        "--corpus-only",
        action="store_true",
        help="Only regenerate e2e/corpus_hibp.json",
    )
    args = ap.parse_args()

    if args.corpus_only:
        write_corpus_hibp()
        return

    if args.full:
        download_full(args.out_dir, args.parallelism, args.force)
    else:
        meta = download_e2e_subset(args.out_dir)
        print(json.dumps(meta, indent=2))
        print("Next:")
        print("  cargo +stable-x86_64-pc-windows-gnu build -p psa-cli --release")
        print("  python e2e/run_e2e.py --update-baseline")


if __name__ == "__main__":
    main()
