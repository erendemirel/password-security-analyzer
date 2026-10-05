# Language bindings (native FFI)

PSA’s core is Rust. Other languages call it through a small C API ([`crates/psa-ffi`](../crates/psa-ffi), [`include/psa.h`](../include/psa.h)).

**Once per machine / CI**, build the shared library and copy it into the language packages:

```bash
# Windows (GNU toolchain)
powershell -ExecutionPolicy Bypass -File scripts/build_ffi.ps1

# Linux / macOS
bash scripts/build_ffi.sh
```

Then use the package for your language (each folder has a short README):

| Language | Package | Smoke check |
|----------|---------|-------------|
| **Python** | [`packages/psa-python`](../packages/psa-python) | `python packages/psa-python/tests/smoke_test.py` |
| **Go** | [`packages/psa-go`](../packages/psa-go) | `cd packages/psa-go && go test .` |
| **Java** | [`packages/psa-java`](../packages/psa-java) | `cd packages/psa-java && mvn test` |
| **Node.js** (server) | [`packages/psa-node`](../packages/psa-node) | `cd packages/psa-node && npm i && npm test` |
| **.NET** | [`packages/psa-dotnet`](../packages/psa-dotnet) | `cd packages/psa-dotnet && dotnet run --project Smoke` |
| **C++** | [`packages/psa-cpp`](../packages/psa-cpp) | `g++ -std=c++17 -Iinclude smoke.cpp -Llib -lpsa_ffi -o smoke && ./smoke` |
| **Ruby** | [`packages/psa-ruby`](../packages/psa-ruby) | `cd packages/psa-ruby && bundle install && ruby test/smoke_test.rb` |
| **Browser / WASM** | [`packages/psa-js`](../packages/psa-js) | `npm run build:wasm` |

If the loader cannot find the native library, set `PSA_FFI_PATH` to the `.dll` / `.so` / `.dylib`.

Call samples: [Usage in the root README](../README.md#usage). There, `analyze_offline` means **no network** (local scoring); it is not the same as “local HIBP database.” Use `analyze` for live HIBP, or pass `hibp_offline_path` for an offline breach store.
