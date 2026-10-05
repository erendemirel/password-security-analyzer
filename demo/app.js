import init, { analyze, analyzeOffline } from "./pkg/psa_wasm.js";

const passwordEl = document.getElementById("password");
const showEl = document.getElementById("show");
const hibpEl = document.getElementById("hibp");
const analyzeBtn = document.getElementById("analyze");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");

let ready = false;
let seq = 0;

function setStatus(text, state = "") {
  statusEl.textContent = text;
  if (state) statusEl.dataset.state = state;
  else delete statusEl.dataset.state;
}

function fmt(n) {
  if (n == null || Number.isNaN(n)) return "—";
  if (typeof n === "number" && n >= 1e6) return n.toExponential(2);
  if (typeof n === "number") return Number.isInteger(n) ? String(n) : n.toFixed(2);
  return String(n);
}

function render(r) {
  const label = r.label ?? "none";
  const reasons = Array.isArray(r.reasons) && r.reasons.length ? r.reasons.join(", ") : "none";
  const breach = r.breach || {};
  const pwned = Boolean(breach.pwned);

  resultEl.hidden = false;
  resultEl.innerHTML = `
    <div><span class="badge" data-label="${label}">${label.replace("_", " ")}</span></div>
    <dl class="metrics">
      <div class="metric"><dt>strength_bits</dt><dd>${fmt(r.strength_bits)}</dd></div>
      <div class="metric"><dt>keyspace_bits</dt><dd>${fmt(r.keyspace_bits)}</dd></div>
      <div class="metric"><dt>guess_number</dt><dd>${fmt(r.guess_number)}</dd></div>
      <div class="metric"><dt>aborted</dt><dd>${r.aborted ? "true" : "false"}</dd></div>
    </dl>
    <p class="breach" data-pwned="${pwned}">
      ${
        pwned
          ? `Found in breaches (${fmt(breach.occurrences)} occurrences, ${breach.source || "hibp"}).`
          : hibpEl.checked
            ? `Not found in HIBP (${breach.source || "hibp_range"}).`
            : "Breach check skipped (offline scoring)."
      }
    </p>
    <p class="reasons"><strong>reasons:</strong> ${reasons}</p>
  `;
}

async function score() {
  if (!ready) return;
  const password = passwordEl.value;
  const my = ++seq;

  if (!password) {
    resultEl.hidden = true;
    setStatus("Enter a password, then click Analyze.");
    return;
  }

  analyzeBtn.disabled = true;
  try {
    setStatus(hibpEl.checked ? "Checking (includes HIBP)…" : "Scoring locally…");
    let r;
    if (hibpEl.checked) {
      r = await analyze(password, {
        user_agent: "password-security-analyzer-demo/0.1.0",
        skip_breach: false,
        skip_model: false,
      });
    } else {
      r = analyzeOffline(password, false);
    }
    if (my !== seq) return;
    render(r);
    setStatus(hibpEl.checked ? "Scored with live HIBP." : "Scored offline (no network).");
  } catch (err) {
    if (my !== seq) return;
    console.error(err);
    resultEl.hidden = true;
    setStatus(err?.message || String(err), "error");
  } finally {
    if (ready) analyzeBtn.disabled = false;
  }
}

showEl.addEventListener("change", () => {
  passwordEl.type = showEl.checked ? "text" : "password";
});
analyzeBtn.addEventListener("click", () => {
  score();
});
passwordEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    score();
  }
});

try {
  await init();
  ready = true;
  analyzeBtn.disabled = false;
  setStatus("Engine ready. Enter a password and click Analyze.");
} catch (err) {
  console.error(err);
  analyzeBtn.disabled = true;
  setStatus(
    "Failed to load WASM. Build with scripts/build_demo.sh (or deploy on Netlify).",
    "error"
  );
}
