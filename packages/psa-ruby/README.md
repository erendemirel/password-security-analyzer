# Ruby binding (FFI gem → psa-ffi)

```bash
powershell -ExecutionPolicy Bypass -File scripts/build_ffi.ps1
cd packages/psa-ruby
bundle install
ruby test/smoke_test.rb
```

```ruby
require "password_security_analyzer"
r = PasswordSecurityAnalyzer.analyze_offline("password")
puts r["label"]
```

Set `PSA_FFI_PATH` to override the shared library location. Native lib lives in `lib/native/` after `build_ffi`.
