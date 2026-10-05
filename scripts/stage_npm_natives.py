#!/usr/bin/env python3
"""Copy CI native artifacts into npm platform packages and main package optionalDeps versions."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# artifact folder suffix -> (npm platform id, lib filename)
MAP = {
    "linux-x64": ("linux-x64", "libpsa_ffi.so"),
    "darwin-arm64": ("darwin-arm64", "libpsa_ffi.dylib"),
    "darwin-x64": ("darwin-x64", "libpsa_ffi.dylib"),
    "windows-x64": ("win32-x64", "psa_ffi.dll"),
}


def main() -> None:
    artifacts = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts")
    npm_root = ROOT / "packages/psa-node/npm"
    version = json.loads((ROOT / "packages/psa-node/package.json").read_text())["version"]

    plats = []
    for art_suffix, (npm_plat, lib_name) in MAP.items():
        src = artifacts / f"psa_ffi-{art_suffix}" / lib_name
        if not src.is_file():
            raise SystemExit(f"missing {src}")
        dest_dir = npm_root / npm_plat
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest_dir / lib_name)
        os_name, cpu = npm_plat.split("-", 1)
        pkg = {
            "name": f"@psa/password-security-analyzer-native-{npm_plat}",
            "version": version,
            "description": f"Native psa_ffi binary for {npm_plat}",
            "license": "MIT",
            "os": [os_name],
            "cpu": [cpu],
            "files": [lib_name],
            "publishConfig": {"access": "public"},
        }
        (dest_dir / "package.json").write_text(json.dumps(pkg, indent=2) + "\n")
        plats.append(npm_plat)
        print(f"staged {npm_plat}")

    main = ROOT / "packages/psa-node/package.json"
    j = json.loads(main.read_text())
    j["version"] = version
    j["optionalDependencies"] = {
        f"@psa/password-security-analyzer-native-{p}": version for p in plats
    }
    main.write_text(json.dumps(j, indent=2) + "\n")
    print("updated main package.json optionalDependencies")


if __name__ == "__main__":
    main()
