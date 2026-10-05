#!/usr/bin/env bash
# Build psa-ffi release shared library and copy into language packages.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Building psa-ffi (release)..."
cargo build -p psa-ffi --release

OS="$(uname -s)"
case "$OS" in
  Linux*)  LIB="target/release/libpsa_ffi.so"; NAME="libpsa_ffi.so" ;;
  Darwin*) LIB="target/release/libpsa_ffi.dylib"; NAME="libpsa_ffi.dylib" ;;
  *) echo "Unsupported OS: $OS (use build_ffi.ps1 on Windows)"; exit 1 ;;
esac

if [[ ! -f "$LIB" ]]; then
  echo "missing $LIB" >&2
  exit 1
fi

DESTS=(
  "packages/psa-python/password_security_analyzer/lib"
  "packages/psa-go/lib"
  "packages/psa-java/src/main/resources/native"
  "packages/psa-node/lib"
  "packages/psa-dotnet/lib"
  "packages/psa-cpp/lib"
  "packages/psa-ruby/lib/native"
)

for d in "${DESTS[@]}"; do
  mkdir -p "$d"
  cp "$LIB" "$d/$NAME"
  echo "Copied $NAME -> $d"
done

cp include/psa.h packages/psa-go/psa.h
cp include/psa.h packages/psa-java/psa.h
mkdir -p packages/psa-cpp/include
cp include/psa.h packages/psa-cpp/include/psa.h
echo "Done."
