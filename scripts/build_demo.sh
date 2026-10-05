#!/usr/bin/env bash
# Build psa-wasm (--target web) into demo/pkg for the Netlify / static demo.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v rustup >/dev/null 2>&1; then
  echo "Installing Rust (rustup)..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true

# Host toolchain for build scripts / proc-macros.
# On Windows+Git Bash, MSVC often breaks (no VS tools, or Unix `link` shadows link.exe).
# Prefer the GNU toolchain there; Netlify/Linux keep plain stable.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    HOST_TC="${RUSTUP_TOOLCHAIN:-stable-x86_64-pc-windows-gnu}"
    ;;
  *)
    HOST_TC="${RUSTUP_TOOLCHAIN:-stable}"
    ;;
esac

echo "Using toolchain: $HOST_TC"
rustup toolchain install "$HOST_TC" --profile minimal
rustup target add wasm32-unknown-unknown --toolchain "$HOST_TC"
export RUSTUP_TOOLCHAIN="$HOST_TC"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "Installing wasm-pack..."
  curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
  export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "Building psa-wasm (web) → demo/pkg ..."
rm -rf demo/pkg
# Clear MSVC-flavored build-script artifacts that confuse a GNU rebuild.
cargo +"$HOST_TC" clean -p psa-wasm 2>/dev/null || true

wasm-pack build crates/psa-wasm \
  --target web \
  --release \
  --out-dir ../../demo/pkg

echo "Demo assets ready under demo/"
