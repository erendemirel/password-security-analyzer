# Install / build

Build **from this repository** (CLI, WASM package, or Rust path dependency). This is for integrators and contributors working from a checkout — not a registry `pip install` / NuGet guide. For calling the library from Python, Go, Java, and other languages after building the shared library, see [bindings.md](bindings.md).

## Rust CLI

```bash
cargo build -p psa-cli --release
./target/release/psa analyze-offline 'correcthorsebatterystaple'
./target/release/psa analyze 'password'          # hits HIBP
./target/release/psa check-pwned 'password'
./target/release/psa analyze-offline 'secret' --no-model
# Batch: one password per stdin line → NDJSON (used by leak eval)
printf 'password\nhunter2\n' | ./target/release/psa analyze-offline --batch
```

On Windows without MSVC, use the GNU toolchain:

```bash
cargo +stable-x86_64-pc-windows-gnu build -p psa-cli --release
```

## JavaScript / WASM

```bash
# requires wasm-pack (https://rustwasm.github.io/wasm-pack/)
cd packages/psa-js
# Windows without MSVC:
#   set RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-gnu
npm run build:wasm
```

```js
import init, { analyze, analyzeOffline } from "@psa/password-security-analyzer";

await init();
const r = await analyze("password", {
  user_agent: "MyApp/1.0",
  skip_model: true, // HIBP + keyspace bits only
});
const offline = analyzeOffline("password", true); // keyspace bits only
```

## As a Rust dependency

```toml
psa-core = { path = "crates/psa-core" }
```

```rust
use psa_core::{analyze_offline, AnalyzeOptions, analyze};

let r = analyze_offline("hunter2", None)?;
println!("{:?}", r.label);
```

## Workspace layout

```
crates/psa-core   # library
crates/psa-cli    # `psa` binary
crates/psa-ffi    # C ABI (cdylib) for language bindings
crates/psa-wasm   # wasm-bindgen (browsers)
packages/psa-js   # npm WASM wrapper
packages/psa-python / psa-go / psa-java / psa-node / psa-dotnet / psa-cpp / psa-ruby  # native FFI wrappers
models/           # markov4.bin + mc_curve.bin + known.bin
scripts/          # train_markov.py, eval_leak.py, build_ffi.*
conformance/      # golden vectors
docs/             # install, training, bindings, eval, HIBP
```
