# PasswordSecurityAnalyzer (.NET)

```bash
dotnet add package PasswordSecurityAnalyzer
```

```csharp
using Psa;
var r = PasswordSecurityAnalyzer.AnalyzeOffline("password");
Console.WriteLine(r["label"]);
```

Advisory only — see [root README](../../README.md#security-notice-server-side-use). From source: [docs/bindings.md](../../docs/bindings.md).
