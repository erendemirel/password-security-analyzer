#!/usr/bin/env python3
"""Rename a wheel to a target PEP 427 platform tag."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 4:
        print("usage: retag_wheel.py WHEEL PLATFORM_TAG OUT_DIR", file=sys.stderr)
        sys.exit(2)
    wheel = Path(sys.argv[1])
    tag = sys.argv[2]
    out = Path(sys.argv[3])
    out.mkdir(parents=True, exist_ok=True)
    # name-ver-pyTAG-abiTAG-platTAG.whl
    parts = wheel.name[:-4].split("-")
    if len(parts) < 5:
        print(f"unexpected wheel name: {wheel.name}", file=sys.stderr)
        sys.exit(1)
    # last three are python/abi/platform (platform may contain dots already as one segment)
    # setuptools produces e.g. password_security_analyzer-0.1.0-py3-none-any.whl
    name_ver = "-".join(parts[:-3])
    py_tag, abi_tag, _plat = parts[-3], parts[-2], parts[-1]
    new_name = f"{name_ver}-{py_tag}-{abi_tag}-{tag}.whl"
    dest = out / new_name
    shutil.copy2(wheel, dest)
    print(f"{wheel.name} -> {dest}")


if __name__ == "__main__":
    main()
