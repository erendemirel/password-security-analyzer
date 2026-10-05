# Go binding (cgo) for psa-ffi

```bash
powershell -ExecutionPolicy Bypass -File scripts/build_ffi.ps1
cd packages/psa-go
# Windows: ensure the DLL is findable
set PATH=%CD%\lib;%CD%\..\..\target\release;%PATH%
go test .
```

```go
r, err := psa.AnalyzeOffline("password", nil)
fmt.Println(r["label"])
```

Requires a C toolchain (MinGW/GCC matching the Rust GNU target on Windows).
