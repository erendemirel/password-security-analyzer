# .NET binding (P/Invoke → psa-ffi)

```bash
powershell -ExecutionPolicy Bypass -File scripts/build_ffi.ps1
cd packages/psa-dotnet
dotnet run --project Smoke
```

On Windows, ensure `lib/psa_ffi.dll` exists (copied by `build_ffi`) or set `PSA_FFI_PATH`.

```csharp
using Psa;
var r = PasswordSecurityAnalyzer.AnalyzeOffline("password");
Console.WriteLine(r["label"]);
```
