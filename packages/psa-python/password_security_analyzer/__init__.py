"""Advisory password strength analyzer (native FFI to psa-core).

Does not authorize account creation — keep server-side policy checks.
"""

from __future__ import annotations

import json
import os
import sys
from ctypes import CDLL, c_char_p, c_void_p, cast
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "analyze",
    "analyze_offline",
    "check_pwned",
    "model_info",
    "PsaError",
]


class PsaError(RuntimeError):
    pass


def _lib_candidates() -> list[Path]:
    here = Path(__file__).resolve().parent
    repo = here.parents[3]  # .../packages/psa-python/password_security_analyzer -> repo
    env = os.environ.get("PSA_FFI_PATH")
    out: list[Path] = []
    if env:
        out.append(Path(env))
    lib_dir = here / "lib"
    if sys.platform == "win32":
        out += [lib_dir / "psa_ffi.dll", repo / "target" / "release" / "psa_ffi.dll"]
    elif sys.platform == "darwin":
        out += [
            lib_dir / "libpsa_ffi.dylib",
            repo / "target" / "release" / "libpsa_ffi.dylib",
        ]
    else:
        out += [
            lib_dir / "libpsa_ffi.so",
            repo / "target" / "release" / "libpsa_ffi.so",
        ]
    return out


def _load_lib() -> CDLL:
    last: Exception | None = None
    for path in _lib_candidates():
        if not path.exists():
            continue
        try:
            return CDLL(str(path))
        except OSError as e:
            last = e
    raise PsaError(
        "psa_ffi shared library not found. Build with:\n"
        "  pwsh scripts/build_ffi.ps1   # or scripts/build_ffi.sh\n"
        "Or set PSA_FFI_PATH to the .dll/.so/.dylib"
        + (f"\nLast error: {last}" if last else "")
    )


_LIB = _load_lib()
_LIB.psa_analyze_offline.argtypes = [c_char_p, c_char_p]
_LIB.psa_analyze_offline.restype = c_void_p
_LIB.psa_analyze.argtypes = [c_char_p, c_char_p]
_LIB.psa_analyze.restype = c_void_p
_LIB.psa_check_pwned.argtypes = [c_char_p, c_char_p]
_LIB.psa_check_pwned.restype = c_void_p
_LIB.psa_model_info.argtypes = []
_LIB.psa_model_info.restype = c_void_p
_LIB.psa_string_free.argtypes = [c_void_p]
_LIB.psa_string_free.restype = None
_LIB.psa_last_error.argtypes = []
_LIB.psa_last_error.restype = c_char_p


def _options_bytes(options: Optional[dict[str, Any]]) -> Optional[bytes]:
    if options is None:
        return None
    return json.dumps(options).encode("utf-8")


def _call(fn, password: str, options: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    pw = password.encode("utf-8")
    opt = _options_bytes(options)
    ptr = fn(pw, opt)
    if not ptr:
        err = _LIB.psa_last_error() or b"unknown error"
        raise PsaError(err.decode("utf-8", errors="replace"))
    try:
        raw = cast(ptr, c_char_p).value
        if raw is None:
            raise PsaError("null JSON from psa-ffi")
        return json.loads(raw.decode("utf-8"))
    finally:
        _LIB.psa_string_free(ptr)


def analyze_offline(password: str, options: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Score without network HIBP (unless hibp_offline is set)."""
    return _call(_LIB.psa_analyze_offline, password, options)


def analyze(password: str, options: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Score with live HIBP unless skip_breach / hibp_offline."""
    return _call(_LIB.psa_analyze, password, options)


def check_pwned(password: str, options: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Return breach JSON only."""
    return _call(_LIB.psa_check_pwned, password, options)


def model_info() -> dict[str, Any]:
    ptr = _LIB.psa_model_info()
    if not ptr:
        err = _LIB.psa_last_error() or b"unknown error"
        raise PsaError(err.decode("utf-8", errors="replace"))
    try:
        raw = cast(ptr, c_char_p).value
        assert raw is not None
        return json.loads(raw.decode("utf-8"))
    finally:
        _LIB.psa_string_free(ptr)
