# Build from source

Clone/build details when you are not using a registry install from the [root README](../README.md#installation).

## Artifact sizes

Each install embeds the scoring model, so downloads are large. Approximate download size **per platform** (what you get for your OS/CPU):

| Install | Approx. size |
|---------|----------------|
| Rust CLI (`cargo build -p psa-cli --release` → `psa`) | **~23 MB** binary |
| Rust library (`psa-core` path/git dep; embeds in your binary) | **~15–23 MB** added to the final binary |
| Python (`pip install password-security-analyzer`) | **~22 MB** wheel |
| Node native (`@psa/password-security-analyzer-native`) | **~22 MB** (one platform package) |
| Node / browser WASM (`@psa/password-security-analyzer`) | **~15 MB** |
| .NET (`PasswordSecurityAnalyzer`) | **~22 MB** per RID in the nupkg (multi-OS pack is larger) |
| Java (Maven) | **~22 MB** per OS inside the jar (multi-OS jar is larger) |
| Ruby (`password_security_analyzer`) | **~90 MB** fat gem (linux + mac + windows) |
| Go module (`psa-go` with prebuilt libs) | **~22 MB** per `GOOS`/`GOARCH` you vendor |
| C++ / GitHub Release shared lib | **~22 MB** |

The Ruby gem and multi-OS Java/NuGet packages are bigger because they ship several platforms in one artifact.

## Shared native library

```bash
# Windows (GNU toolchain)
powershell -ExecutionPolicy Bypass -File scripts/build_ffi.ps1

# Linux / macOS
bash scripts/build_ffi.sh
```

Override the library path with `PSA_FFI_PATH`. Language-specific smoke commands: [bindings.md](bindings.md).

## Rust CLI

```bash
cargo build -p psa-cli --release
./target/release/psa analyze-offline 'correcthorsebatterystaple'
./target/release/psa analyze 'password'          # hits HIBP
./target/release/psa check-pwned 'password'
./target/release/psa analyze-offline 'secret' --no-model
printf 'password\nhunter2\n' | ./target/release/psa analyze-offline --batch
```

On Windows without MSVC:

```bash
cargo +stable-x86_64-pc-windows-gnu build -p psa-cli --release
```

## JavaScript / WASM

```bash
cd packages/psa-js
# Windows without MSVC: set RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-gnu
npm run build:wasm
```

Published package: `@psa/password-security-analyzer` (built in release CI).

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
packages/psa-*    # language wrappers
models/           # markov4.bin + mc_curve.bin + known.bin
```
