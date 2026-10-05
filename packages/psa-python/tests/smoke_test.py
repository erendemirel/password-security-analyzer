#!/usr/bin/env python3
"""Smoke tests for the Python FFI binding."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from password_security_analyzer import analyze_offline, model_info  # noqa: E402


def main() -> int:
    info = model_info()
    assert info.get("advisory") is True, info

    weak = analyze_offline("password")
    assert weak.get("label") == "weak", weak

    alpha = analyze_offline("abcdefghijklmnopqrstuvwxyz")
    assert alpha.get("label") == "weak", alpha
    assert any(r == "sequential_run" for r in alpha.get("reasons") or []), alpha

    strong = analyze_offline("kR7!mQx#9vLp$2nW")
    assert strong.get("label") in ("strong", "very_strong"), strong

    print("python smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
