# Advisory password strength analyzer (Python FFI).
# Does not authorize account creation.

```bash
# From repo root (Windows GNU):
pwsh scripts/build_ffi.ps1
python packages/psa-python/tests/smoke_test.py
```

```python
from password_security_analyzer import analyze_offline

r = analyze_offline("password")
print(r["label"], r["strength_bits"], r["reasons"])
```

Set `PSA_FFI_PATH` to override the shared library location.
