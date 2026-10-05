# C++ binding (header-only → psa-ffi)

```bash
powershell -ExecutionPolicy Bypass -File scripts/build_ffi.ps1
cd packages/psa-cpp

# Windows (MSYS2/MinGW g++)
g++ -std=c++17 -Iinclude -I. -I../../include smoke.cpp -Llib -L../../target/release -lpsa_ffi -o smoke.exe
# DLL must be findable:
set PATH=%CD%\lib;%CD%\..\..\target\release;%PATH%
./smoke.exe
```

```cpp
#include "psa.hpp"
std::cout << psa::analyze_offline("password") << "\n";
```

`include/psa.hpp` wraps [`psa.h`](../../include/psa.h). JSON is returned as `std::string` (same shape as the CLI).
