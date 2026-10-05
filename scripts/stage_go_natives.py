#!/usr/bin/env python3
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAP = {
    "linux-x64": ("linux_amd64", "libpsa_ffi.so"),
    "darwin-arm64": ("darwin_arm64", "libpsa_ffi.dylib"),
    "darwin-x64": ("darwin_amd64", "libpsa_ffi.dylib"),
    "windows-x64": ("windows_amd64", "psa_ffi.dll"),
}


def main() -> None:
    artifacts = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts")
    base = ROOT / "packages/psa-go/lib"
    for art, (subdir, lib) in MAP.items():
        src_dir = artifacts / f"psa_ffi-{art}"
        src = src_dir / lib
        if not src.is_file():
            raise SystemExit(f"missing {src}")
        dest = base / subdir
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest / lib)
        # Windows import lib for cgo if present
        if art == "windows-x64":
            for name in ("libpsa_ffi.dll.a", "psa_ffi.dll.a"):
                imp = src_dir / name
                if imp.is_file():
                    shutil.copy2(imp, dest / "libpsa_ffi.dll.a")
                    break
        print(f"staged {subdir}/{lib}")


if __name__ == "__main__":
    main()
