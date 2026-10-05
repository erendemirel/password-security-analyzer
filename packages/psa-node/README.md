# Native Node.js bindings (koffi → psa-ffi)

For **browsers**, use [`../psa-js`](../psa-js) (WASM) instead.

```bash
pwsh scripts/build_ffi.ps1   # or scripts/build_ffi.sh
cd packages/psa-node
npm install
npm test
```

```js
const { analyzeOffline } = require('@psa/password-security-analyzer-native');
console.log(analyzeOffline('password').label);
```

Set `PSA_FFI_PATH` to override the shared library path.
