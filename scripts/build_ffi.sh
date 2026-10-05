#!/usr/bin/env bash
# Build psa-ffi release shared library and copy into language packages.
# Set PSA_FFI_COPY_STATIC=1 to also copy archive/import libs for local linking.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Building psa-ffi (release)..."
cargo build -p psa-ffi --release

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux*)
    LIB="target/release/libpsa_ffi.so"
    NAME="libpsa_ffi.so"
    case "$ARCH" in
      x86_64|amd64) GO_DIR="linux_amd64"; JAVA_DIR="linux-x86_64"; DOTNET_RID="linux-x64"; RUBY_DIR="linux_amd64"; NODE_PLAT="linux-x64" ;;
      aarch64|arm64) GO_DIR="linux_arm64"; JAVA_DIR="linux-aarch64"; DOTNET_RID="linux-arm64"; RUBY_DIR="linux_arm64"; NODE_PLAT="linux-arm64" ;;
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  Darwin*)
    LIB="target/release/libpsa_ffi.dylib"
    NAME="libpsa_ffi.dylib"
    case "$ARCH" in
      x86_64) GO_DIR="darwin_amd64"; JAVA_DIR="darwin-x86_64"; DOTNET_RID="osx-x64"; RUBY_DIR="darwin_amd64"; NODE_PLAT="darwin-x64" ;;
      arm64) GO_DIR="darwin_arm64"; JAVA_DIR="darwin-aarch64"; DOTNET_RID="osx-arm64"; RUBY_DIR="darwin_arm64"; NODE_PLAT="darwin-arm64" ;;
      *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  *) echo "Unsupported OS: $OS (use build_ffi.ps1 on Windows)"; exit 1 ;;
esac

if [[ ! -f "$LIB" ]]; then
  echo "missing $LIB" >&2
  exit 1
fi

DESTS=(
  "packages/psa-python/password_security_analyzer/lib"
  "packages/psa-go/lib/${GO_DIR}"
  "packages/psa-java/src/main/resources/native/${JAVA_DIR}"
  "packages/psa-node/lib"
  "packages/psa-dotnet/runtimes/${DOTNET_RID}/native"
  "packages/psa-dotnet/lib"
  "packages/psa-cpp/lib"
  "packages/psa-ruby/lib/native/${RUBY_DIR}"
)

for d in "${DESTS[@]}"; do
  mkdir -p "$d"
  cp "$LIB" "$d/$NAME"
  echo "Copied $NAME -> $d"
done

# Also stage into npm platform package dir when present
NODE_NPM="packages/psa-node/npm/${NODE_PLAT}"
if [[ -d "$NODE_NPM" ]] || mkdir -p "$NODE_NPM"; then
  mkdir -p "$NODE_NPM"
  cp "$LIB" "$NODE_NPM/$NAME"
fi

cp include/psa.h packages/psa-go/psa.h
cp include/psa.h packages/psa-java/psa.h
mkdir -p packages/psa-cpp/include
cp include/psa.h packages/psa-cpp/include/psa.h
echo "Done."
