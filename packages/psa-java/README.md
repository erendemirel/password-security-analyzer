# Java binding (JNA → psa-ffi)

```bash
pwsh scripts/build_ffi.ps1
cd packages/psa-java
mvn test
```

```java
Map<String, Object> r = PasswordSecurityAnalyzer.analyzeOffline("password", null);
System.out.println(r.get("label"));
```

Requires JDK 11+ and Maven. Set `PSA_FFI_PATH` to the absolute path of `psa_ffi.dll` / `.so` / `.dylib` if needed.
