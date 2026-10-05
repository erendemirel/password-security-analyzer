#!/usr/bin/env python3
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAP = {
    "linux-x64": ("linux-x64", "libpsa_ffi.so"),
    "darwin-arm64": ("osx-arm64", "libpsa_ffi.dylib"),
    "darwin-x64": ("osx-x64", "libpsa_ffi.dylib"),
    "windows-x64": ("win-x64", "psa_ffi.dll"),
}


def main() -> None:
    artifacts = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts")
    base = ROOT / "packages/psa-dotnet/runtimes"
    for art, (rid, lib) in MAP.items():
        src = artifacts / f"psa_ffi-{art}" / lib
        if not src.is_file():
            raise SystemExit(f"missing {src}")
        dest = base / rid / "native"
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / lib)
        print(f"staged {rid}/{lib}")


if __name__ == "__main__":
    main()
