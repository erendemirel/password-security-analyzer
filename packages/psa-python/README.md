# password-security-analyzer (Python)

Advisory password strength analyzer. Does not authorize account creation.

```bash
pip install password-security-analyzer
```

```python
from password_security_analyzer import analyze_offline
print(analyze_offline("password")["label"])
```

Security / DoS notice: see the [root README](../../README.md#security-notice-server-side-use).

From source: [docs/bindings.md](../../docs/bindings.md).
