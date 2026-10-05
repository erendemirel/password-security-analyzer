# @psa/password-security-analyzer-native

Native Node bindings (koffi → psa-ffi). Does not authorize account creation.

```bash
npm i @psa/password-security-analyzer-native
```

Platform binaries ship as optionalDependencies (`-linux-x64`, `-darwin-arm64`, `-darwin-x64`, `-win32-x64`).

```js
const { analyzeOffline } = require("@psa/password-security-analyzer-native");
console.log(analyzeOffline("password").label);
```

Browser / WASM: `@psa/password-security-analyzer`. Security notice: [root README](../../README.md#security-notice-server-side-use).
