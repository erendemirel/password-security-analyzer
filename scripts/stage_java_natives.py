#!/usr/bin/env python3
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAP = {
    "linux-x64": ("linux-x86_64", "libpsa_ffi.so"),
    "darwin-arm64": ("darwin-aarch64", "libpsa_ffi.dylib"),
    "darwin-x64": ("darwin-x86_64", "libpsa_ffi.dylib"),
    "windows-x64": ("windows-x86_64", "psa_ffi.dll"),
}


def main() -> None:
    artifacts = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts")
    base = ROOT / "packages/psa-java/src/main/resources/native"
    for art, (subdir, lib) in MAP.items():
        src = artifacts / f"psa_ffi-{art}" / lib
        if not src.is_file():
            raise SystemExit(f"missing {src}")
        dest = base / subdir
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / lib)
        print(f"staged {subdir}/{lib}")


if __name__ == "__main__":
    main()
