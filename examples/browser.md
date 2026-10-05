# Example: browser usage (after `npm run build:wasm` in packages/psa-js)

```html
<script type="module">
  import init, { analyze, analyzeOffline } from "./pkg/psa_wasm.js";

  await init();

  // Live offline preview (no HIBP)
  const preview = analyzeOffline("hunter2");
  console.log("preview", preview);

  // Full advisory check including HIBP (blur/submit — not every keystroke)
  const result = await analyze("hunter2", {
    user_agent: "MyWebApp/1.0",
  });
  console.log(result.label, result.strength_bits, result.breach);
</script>
```

Remember: results are **advisory**. Your Auth API must still enforce basic password policy before creating accounts.
