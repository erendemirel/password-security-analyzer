# psa-cpp

C++ header wrapper over psa-ffi. **Not** published to a C++ package manager in v1.

Download `psa.h`, `psa.hpp`, and the matching shared library from the [GitHub Release](https://github.com/erendemirel/password-security-analyzer/releases) for your version tag.

```cpp
#include "psa.hpp"
std::cout << psa::analyze_offline("password") << "\n";
```

From-source build: [docs/bindings.md](../../docs/bindings.md). Advisory only — see [root README](../../README.md#security-notice-server-side-use).
