/**
 * Native Node bindings via koffi → psa_ffi (same C ABI as Python/Go/Java).
 * Build the shared lib first: pwsh scripts/build_ffi.ps1
 * Browser / WASM: use @psa/password-security-analyzer instead.
 */
const fs = require('fs');
const path = require('path');
const koffi = require('koffi');

function resolveLib() {
  if (process.env.PSA_FFI_PATH && fs.existsSync(process.env.PSA_FFI_PATH)) {
    return process.env.PSA_FFI_PATH;
  }
  const libDir = path.join(__dirname, 'lib');
  const release = path.join(__dirname, '..', '..', 'target', 'release');
  const names =
    process.platform === 'win32'
      ? ['psa_ffi.dll']
      : process.platform === 'darwin'
        ? ['libpsa_ffi.dylib']
        : ['libpsa_ffi.so'];
  for (const n of names) {
    for (const dir of [libDir, release]) {
      const p = path.join(dir, n);
      if (fs.existsSync(p)) return p;
    }
  }
  throw new Error(
    'psa_ffi shared library not found. Run: pwsh scripts/build_ffi.ps1 (or scripts/build_ffi.sh)\n' +
      'Or set PSA_FFI_PATH'
  );
}

const lib = koffi.load(resolveLib());

const psa_analyze_offline = lib.func('psa_analyze_offline', 'void *', ['str', 'str']);
const psa_analyze = lib.func('psa_analyze', 'void *', ['str', 'str']);
const psa_check_pwned = lib.func('psa_check_pwned', 'void *', ['str', 'str']);
const psa_model_info = lib.func('psa_model_info', 'void *', []);
const psa_string_free = lib.func('psa_string_free', 'void', ['void *']);
const psa_last_error = lib.func('psa_last_error', 'str', []);

function readCString(ptr) {
  const view = koffi.view(ptr, 8 * 1024 * 1024);
  const buf = Buffer.from(view);
  const z = buf.indexOf(0);
  return buf.toString('utf8', 0, z < 0 ? buf.length : z);
}

function takeJson(ptr) {
  if (!ptr) {
    throw new Error(psa_last_error() || 'psa-ffi error');
  }
  try {
    return JSON.parse(readCString(ptr));
  } finally {
    psa_string_free(ptr);
  }
}

function optJson(options) {
  return options == null ? null : JSON.stringify(options);
}

function analyzeOffline(password, options) {
  return takeJson(psa_analyze_offline(password, optJson(options)));
}

function analyze(password, options) {
  return takeJson(psa_analyze(password, optJson(options)));
}

function checkPwned(password, options) {
  return takeJson(psa_check_pwned(password, optJson(options)));
}

function modelInfo() {
  return takeJson(psa_model_info());
}

module.exports = {
  analyze,
  analyzeOffline,
  checkPwned,
  modelInfo,
};
