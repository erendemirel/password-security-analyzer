/**
 * Thin JS wrapper around the psa-wasm package.
 *
 * Build first (requires rustc + wasm-pack):
 *   cd packages/psa-js && npm run build:wasm
 *
 * On Windows without MSVC:
 *   set RUSTUP_TOOLCHAIN=stable-x86_64-pc-windows-gnu
 *
 * Advisory only — do not use results to authorize account creation.
 */

export { default, analyze, analyzeOffline, checkPwned } from "./pkg/psa_wasm.js";
