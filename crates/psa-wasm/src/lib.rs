//! Browser / Node WASM bindings (advisory only).

use psa_core::keyspace::keyspace_bits;
use psa_core::hibp::{hash_prefix_suffix, match_range_body, HIBP_RANGE_URL};
use psa_core::types::{
    AnalyzeOptions, AnalyzeResult, BreachPolicy, BreachResult, StrengthLabel,
};
use psa_core::{analyze_offline_with, AnalyzeError};
use serde::Deserialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[derive(Debug, Deserialize)]
struct JsAnalyzeOptions {
    #[serde(default = "default_ua")]
    user_agent: String,
    #[serde(default)]
    skip_breach: bool,
    #[serde(default)]
    skip_model: bool,
}

fn default_ua() -> String {
    "password-security-analyzer/0.1.0-wasm".to_string()
}

async fn fetch_range(prefix: &str, user_agent: &str) -> Result<String, JsValue> {
    let url = format!("{HIBP_RANGE_URL}{prefix}");
    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&url, &opts)?;
    let headers = request.headers();
    headers.set("User-Agent", user_agent)?;
    headers.set("Add-Padding", "true")?;

    let global = js_sys::global();
    let fetch_val = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|_| JsValue::from_str("globalThis.fetch not available"))?;
    let fetch_fn: js_sys::Function = fetch_val
        .dyn_into()
        .map_err(|_| JsValue::from_str("fetch is not a function"))?;
    let promise = fetch_fn
        .call1(&global, request.as_ref())
        .map_err(|_| JsValue::from_str("fetch call failed"))?;
    let resp_value = JsFuture::from(js_sys::Promise::from(promise)).await?;
    let resp: Response = resp_value.dyn_into()?;
    if !resp.ok() {
        return Err(JsValue::from_str(&format!("HIBP status {}", resp.status())));
    }
    let text = JsFuture::from(resp.text()?).await?;
    text.as_string()
        .ok_or_else(|| JsValue::from_str("HIBP body not a string"))
}

fn err_js(e: AnalyzeError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Analyze a password. Options JSON: `{ user_agent?, skip_breach?, skip_model? }`.
#[wasm_bindgen(js_name = analyze)]
pub async fn analyze_js(password: String, options: JsValue) -> Result<JsValue, JsValue> {
    let opts: JsAnalyzeOptions = if options.is_undefined() || options.is_null() {
        JsAnalyzeOptions {
            user_agent: default_ua(),
            skip_breach: false,
            skip_model: false,
        }
    } else {
        serde_wasm_bindgen::from_value(options)
            .map_err(|e| JsValue::from_str(&e.to_string()))?
    };

    let cbits = keyspace_bits(&password);

    if password.is_empty() {
        let r = AnalyzeResult {
            advisory: true,
            aborted: false,
            breach: BreachResult::skipped(),
            guess_number: Some(1.0),
            strength_bits: Some(0.0),
            keyspace_bits: cbits,
            label: Some(StrengthLabel::Weak),
            reasons: vec!["empty_password".to_string()],
        };
        return serde_wasm_bindgen::to_value(&r).map_err(|e| JsValue::from_str(&e.to_string()));
    }

    if !opts.skip_breach {
        let (prefix, suffix) = hash_prefix_suffix(&password);
        let body = fetch_range(&prefix, &opts.user_agent).await?;
        let hit = match_range_body(&body, &suffix)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        if let Some(n) = hit {
            let r = AnalyzeResult::pwned_abort(BreachResult::pwned(n), cbits);
            return serde_wasm_bindgen::to_value(&r).map_err(|e| JsValue::from_str(&e.to_string()));
        }
    }

    let core_opts = AnalyzeOptions {
        user_agent: opts.user_agent.clone(),
        breach_policy: BreachPolicy::Skip,
        timeout_ms: 5_000,
        skip_model: opts.skip_model,
        hibp_offline_path: None,
    };

    // Breach already handled; score offline path (model optional via skip_model).
    let mut result = analyze_offline_with(&password, None, core_opts).map_err(err_js)?;
    if opts.skip_breach {
        result.breach = BreachResult::skipped();
    } else {
        result.breach = BreachResult::clean();
    }

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Offline analyze (no HIBP network call).
/// Pass `skip_model: true` in options via `analyze` for keyspace-bits-only; this helper always scores when a model is embedded.
#[wasm_bindgen(js_name = analyzeOffline)]
pub fn analyze_offline_js(password: String, skip_model: Option<bool>) -> Result<JsValue, JsValue> {
    let opts = AnalyzeOptions {
        breach_policy: BreachPolicy::Skip,
        skip_model: skip_model.unwrap_or(false),
        ..AnalyzeOptions::default()
    };
    let r = analyze_offline_with(&password, None, opts).map_err(err_js)?;
    serde_wasm_bindgen::to_value(&r).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// HIBP-only check.
#[wasm_bindgen(js_name = checkPwned)]
pub async fn check_pwned_js(password: String, user_agent: Option<String>) -> Result<JsValue, JsValue> {
    let ua = user_agent.unwrap_or_else(default_ua);
    let (prefix, suffix) = hash_prefix_suffix(&password);
    let body = fetch_range(&prefix, &ua).await?;
    let hit = match_range_body(&body, &suffix).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let breach = match hit {
        Some(n) => BreachResult::pwned(n),
        None => BreachResult::clean(),
    };
    serde_wasm_bindgen::to_value(&breach).map_err(|e| JsValue::from_str(&e.to_string()))
}
