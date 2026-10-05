#!/usr/bin/env bash
# Thin wrapper — prefer: python3 scripts/sync_version.py
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$ROOT/scripts/sync_version.py" "$@"
