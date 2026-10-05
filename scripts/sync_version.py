#!/usr/bin/env python3
"""Sync package versions from Cargo workspace version (or argv / VERSION env)."""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def cargo_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^version = "([^"]+)"', text)
    if not m:
        raise SystemExit("version not found in Cargo.toml")
    return m.group(1)


def sub_file(path: Path, patterns: list[tuple[str, str]]) -> None:
    if not path.exists():
        print(f"skip missing {path}")
        return
    text = path.read_text(encoding="utf-8")
    orig = text
    for pat, repl in patterns:
        text2, n = re.subn(pat, repl, text, count=1, flags=re.M)
        if n == 0:
            print(f"warn: no match in {path} for {pat!r}")
        text = text2
    if text != orig:
        path.write_text(text, encoding="utf-8")
        print(f"updated {path.relative_to(ROOT)}")
    else:
        print(f"unchanged {path.relative_to(ROOT)}")


def main() -> None:
    version = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("VERSION") or cargo_version()).lstrip("v")
    if not re.match(r"^\d+\.\d+\.\d+", version):
        raise SystemExit(f"invalid version: {version}")
    print(f"Syncing version {version}")

    sub_file(ROOT / "packages/psa-python/pyproject.toml", [
        (r'^version = "[^"]+"', f'version = "{version}"'),
    ])
    for pkg in [
        ROOT / "packages/psa-node/package.json",
        ROOT / "packages/psa-js/package.json",
    ]:
        sub_file(pkg, [(r'"version":\s*"[^"]+"', f'"version": "{version}"')])
    npm_dir = ROOT / "packages/psa-node/npm"
    if npm_dir.is_dir():
        for p in npm_dir.glob("*/package.json"):
            sub_file(p, [(r'"version":\s*"[^"]+"', f'"version": "{version}"')])

    pom = ROOT / "packages/psa-java/pom.xml"
    if pom.exists():
        t = pom.read_text(encoding="utf-8")
        t2 = re.sub(
            r"(<artifactId>password-security-analyzer</artifactId>\s*)<version>[^<]+</version>",
            rf"\1<version>{version}</version>",
            t,
            count=1,
        )
        if t2 != t:
            pom.write_text(t2, encoding="utf-8")
            print("updated packages/psa-java/pom.xml")
        else:
            print("unchanged packages/psa-java/pom.xml")

    sub_file(ROOT / "packages/psa-ruby/password_security_analyzer.gemspec", [
        (r'spec\.version\s*=\s*"[^"]+"', f'spec.version       = "{version}"'),
    ])

    csproj = ROOT / "packages/psa-dotnet/PasswordSecurityAnalyzer.csproj"
    if csproj.exists():
        t = csproj.read_text(encoding="utf-8")
        if "<Version>" in t:
            t2 = re.sub(r"<Version>[^<]+</Version>", f"<Version>{version}</Version>", t, count=1)
        else:
            t2 = t.replace("<PropertyGroup>", f"<PropertyGroup>\n    <Version>{version}</Version>", 1)
        t2 = t2.replace("<TargetFramework>net5.0</TargetFramework>", "<TargetFramework>net6.0</TargetFramework>")
        if t2 != t:
            csproj.write_text(t2, encoding="utf-8")
            print("updated packages/psa-dotnet/PasswordSecurityAnalyzer.csproj")
        else:
            print("unchanged packages/psa-dotnet/PasswordSecurityAnalyzer.csproj")

    # Keep optionalDependencies versions aligned on main node package
    node_pkg = ROOT / "packages/psa-node/package.json"
    if node_pkg.exists():
        import json
        j = json.loads(node_pkg.read_text(encoding="utf-8"))
        if "optionalDependencies" in j:
            j["optionalDependencies"] = {k: version for k in j["optionalDependencies"]}
            node_pkg.write_text(json.dumps(j, indent=2) + "\n", encoding="utf-8")
            print("updated psa-node optionalDependencies versions")

    print("done")


if __name__ == "__main__":
    main()
