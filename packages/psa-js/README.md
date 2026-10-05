# @psa/password-security-analyzer

Browser / bundler WASM binding. Does not authorize account creation.

```bash
npm i @psa/password-security-analyzer
```

```js
import init, { analyzeOffline } from "@psa/password-security-analyzer";
await init();
console.log(analyzeOffline("password").label);
```

Server / native Node: `@psa/password-security-analyzer-native`. Security notice: [root README](../../README.md#security-notice-server-side-use).
