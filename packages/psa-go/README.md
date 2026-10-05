# psa-go

```bash
go get github.com/erendemirel/password-security-analyzer/packages/psa-go@v0.1.0
```

Requires cgo and a C toolchain. Prebuilt shared libraries live under `lib/<GOOS>_<GOARCH>/` in the tagged module.

```go
import psa "github.com/erendemirel/password-security-analyzer/packages/psa-go"

r, err := psa.AnalyzeOffline("password", nil)
```

On Windows, ensure `psa_ffi.dll` is on `PATH` or beside the executable. Advisory only — see [root README](../../README.md#security-notice-server-side-use).
