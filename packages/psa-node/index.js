/**
 * Native Node bindings via koffi → psa_ffi (same C ABI as Python/Go/Java).
 * Browser / WASM: use @psa/password-security-analyzer instead.
 */
const fs = require('fs');
const path = require('path');
const koffi = require('koffi');

function platformPackage() {
  const { platform, arch } = process;
  if (platform === 'linux' && arch === 'x64') return '@psa/password-security-analyzer-native-linux-x64';
  if (platform === 'darwin' && arch === 'arm64') return '@psa/password-security-analyzer-native-darwin-arm64';
  if (platform === 'darwin' && arch === 'x64') return '@psa/password-security-analyzer-native-darwin-x64';
  if (platform === 'win32' && arch === 'x64') return '@psa/password-security-analyzer-native-win32-x64';
  return null;
}

function libFileName() {
  if (process.platform === 'win32') return 'psa_ffi.dll';
  if (process.platform === 'darwin') return 'libpsa_ffi.dylib';
  return 'libpsa_ffi.so';
}

function resolveLib() {
  if (process.env.PSA_FFI_PATH && fs.existsSync(process.env.PSA_FFI_PATH)) {
    return process.env.PSA_FFI_PATH;
  }

  const name = libFileName();
  const localLib = path.join(__dirname, 'lib', name);
  if (fs.existsSync(localLib)) return localLib;

  const pkg = platformPackage();
  if (pkg) {
    try {
      const pkgDir = path.dirname(require.resolve(`${pkg}/package.json`));
      const p = path.join(pkgDir, name);
      if (fs.existsSync(p)) return p;
    } catch (_) {
      /* optionalDependency missing */
    }
  }

  const release = path.join(__dirname, '..', '..', 'target', 'release', name);
  if (fs.existsSync(release)) return release;

  throw new Error(
    'psa_ffi shared library not found. Install the matching optional package, run scripts/build_ffi, or set PSA_FFI_PATH'
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
  analyzeOffline,
  analyze,
  checkPwned,
  modelInfo,
};
