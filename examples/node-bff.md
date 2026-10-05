# Example: Node / BFF usage

```js
import init, { analyze, analyzeOffline } from "@psa/password-security-analyzer";
// After wasm-pack nodejs build, or use bundler output with a fetch polyfill.

await init();

export async function advisePassword(password) {
  const result = await analyze(password, {
    user_agent: "MyBff/1.0",
  });
  // Return score to your API clients — do not treat as authorization.
  return result;
}

// Or offline only:
export function adviseOffline(password) {
  return analyzeOffline(password);
}
```

Then forward the raw password to your Auth API, which runs its own basic checks and creates the user.
