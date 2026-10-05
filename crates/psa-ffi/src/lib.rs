//! C ABI for `psa-core` (advisory password analysis).
//!
//! All `psa_analyze*` functions return heap-allocated UTF-8 JSON.
//! Callers must free with [`psa_string_free`]. On failure they return null
//! and [`psa_last_error`] describes the problem.

#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use psa_core::{
    analyze_offline_with, has_embedded_model, AnalyzeOptions, BreachPolicy,
};
use serde::Deserialize;

#[cfg(feature = "native-http")]
use psa_core::analyze;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_error(msg: impl Into<String>) {
    let msg = msg.into();
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(msg.replace('\0', "")).ok();
    });
}

fn clear_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

fn to_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            set_error("result contained interior NUL");
            ptr::null_mut()
        }
    }
}

fn cstr_to_str<'a>(p: *const c_char) -> Result<&'a str, String> {
    if p.is_null() {
        return Err("null pointer".into());
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|e| e.to_string())
}

#[derive(Debug, Default, Deserialize)]
struct FfiOptions {
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    skip_breach: Option<bool>,
    #[serde(default)]
    skip_model: Option<bool>,
    #[serde(default)]
    no_model: Option<bool>,
    #[serde(default)]
    hibp_offline: Option<String>,
    #[serde(default)]
    hibp_offline_path: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

fn parse_options(options_json: *const c_char, offline_default_skip_breach: bool) -> Result<AnalyzeOptions, String> {
    let raw = if options_json.is_null() {
        "{}"
    } else {
        cstr_to_str(options_json)?
    };
    let ffi: FfiOptions = if raw.trim().is_empty() {
        FfiOptions::default()
    } else {
        serde_json::from_str(raw).map_err(|e| format!("invalid options JSON: {e}"))?
    };

    let skip_model = ffi.skip_model.or(ffi.no_model).unwrap_or(false);
    let hibp_path = ffi.hibp_offline.or(ffi.hibp_offline_path);
    let skip_breach = ffi
        .skip_breach
        .unwrap_or(offline_default_skip_breach && hibp_path.is_none());

    Ok(AnalyzeOptions {
        user_agent: ffi
            .user_agent
            .unwrap_or_else(|| "password-security-analyzer/0.1.0-ffi".into()),
        breach_policy: if skip_breach {
            BreachPolicy::Skip
        } else {
            BreachPolicy::Check
        },
        timeout_ms: ffi.timeout_ms.unwrap_or(5_000),
        skip_model,
        hibp_offline_path: hibp_path,
    })
}

fn run_json<F>(f: F) -> *mut c_char
where
    F: FnOnce() -> Result<String, String> + std::panic::UnwindSafe,
{
    clear_error();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(json)) => to_c_string(json),
        Ok(Err(e)) => {
            set_error(e);
            ptr::null_mut()
        }
        Err(_) => {
            set_error("internal panic in psa-ffi");
            ptr::null_mut()
        }
    }
}

/// Offline analyze (no network HIBP unless `hibp_offline` is set in options).
#[no_mangle]
pub extern "C" fn psa_analyze_offline(
    password: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    run_json(|| {
        let pw = cstr_to_str(password)?;
        let opts = parse_options(options_json, true)?;
        let r = analyze_offline_with(pw, None, opts).map_err(|e| e.to_string())?;
        serde_json::to_string(&r).map_err(|e| e.to_string())
    })
}

/// Online analyze (HIBP over the network unless skipped / offline path set).
#[no_mangle]
pub extern "C" fn psa_analyze(
    password: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    run_json(|| {
        let pw = cstr_to_str(password)?;
        let opts = parse_options(options_json, false)?;
        #[cfg(feature = "native-http")]
        {
            let r = analyze(pw, &opts, None).map_err(|e| e.to_string())?;
            serde_json::to_string(&r).map_err(|e| e.to_string())
        }
        #[cfg(not(feature = "native-http"))]
        {
            let _ = (pw, opts);
            Err("psa_analyze requires native-http feature".into())
        }
    })
}

/// Breach check only (JSON of the breach object).
#[no_mangle]
pub extern "C" fn psa_check_pwned(
    password: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    run_json(|| {
        let pw = cstr_to_str(password)?;
        let mut opts = parse_options(options_json, false)?;
        opts.skip_model = true;
        opts.breach_policy = BreachPolicy::Check;
        #[cfg(feature = "native-http")]
        {
            let r = analyze(pw, &opts, None).map_err(|e| e.to_string())?;
            serde_json::to_string(&r.breach).map_err(|e| e.to_string())
        }
        #[cfg(not(feature = "native-http"))]
        {
            let _ = (pw, opts);
            Err("psa_check_pwned requires native-http feature".into())
        }
    })
}

/// Model / build metadata JSON.
#[no_mangle]
pub extern "C" fn psa_model_info() -> *mut c_char {
    run_json(|| {
        let v = serde_json::json!({
            "embedded_model": has_embedded_model(),
            "advisory": true,
        });
        Ok(v.to_string())
    })
}

/// Free a string returned by this library.
#[no_mangle]
pub unsafe extern "C" fn psa_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(unsafe { CString::from_raw(s) });
}

/// Last error message for this thread (valid until next FFI call). Never null.
#[no_mangle]
pub extern "C" fn psa_last_error() -> *const c_char {
    static EMPTY: &[u8] = b"\0";
    LAST_ERROR.with(|slot| {
        if let Some(ref c) = *slot.borrow() {
            c.as_ptr()
        } else {
            EMPTY.as_ptr() as *const c_char
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn take_json(p: *mut c_char) -> String {
        assert!(!p.is_null(), "err={}", unsafe {
            CStr::from_ptr(psa_last_error()).to_string_lossy()
        });
        unsafe {
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            psa_string_free(p);
            s
        }
    }

    #[test]
    fn offline_password_is_weak() {
        let pw = CString::new("password").unwrap();
        let json = take_json(psa_analyze_offline(pw.as_ptr(), ptr::null()));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["label"], "weak");
    }

    #[test]
    fn offline_alphabet_demoted() {
        let pw = CString::new("abcdefghijklmnopqrstuvwxyz").unwrap();
        let json = take_json(psa_analyze_offline(pw.as_ptr(), ptr::null()));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["label"], "weak");
        let reasons = v["reasons"].as_array().unwrap();
        assert!(reasons.iter().any(|r| r == "sequential_run"));
    }

    #[test]
    fn model_info_ok() {
        let json = take_json(psa_model_info());
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["advisory"], true);
        assert_eq!(v["embedded_model"], has_embedded_model());
    }
}
