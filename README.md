# Password Security Analyzer

Helps your app tell users whether a password looks easy to guess and whether it has shown up in known breaches.

It runs on the device or in your backend, you embed a library (or CLI). There is no PSA cloud service that receives the password.

**Try it:** [Test it here](https://password-security-analyzer-test.netlify.app) [![Netlify Status](https://api.netlify.com/api/v1/badges/0bfb54c3-5db6-458a-9607-a86ab6e62dfc/deploy-status)](https://app.netlify.com/projects/password-security-analyzer-test/deploys)

## How it works

Real attackers rarely try every possible string in alphabetical order. They try **common passwords and patterns first**, then rarer ones. PSA mirrors that with a few layers:

1. **Breach check**: If the password already appears in HIBP leaked passwords database, treat it as weak and stop. No model needed: a known leak is enough for a warning.
2. **Guessability model**: A Markov model trained on public wordlists estimates how “typical” the string looks; a Monte Carlo curve turns that into an estimated **guess number**, then `strength_bits = log2(guess_number)` and a `label`. This is the main “will this be guessed?” signal.
3. **Pattern checks**: Some easy shapes (long alphabets, UUIDs, hex digests) look unlikely character-by-character, so the model can overrate them. Detectors can only push the label **weaker**, never stronger.
4. **Entropy (keyspace bits)**: Classic combinatorial size, roughly `length × log2(alphabet)` if someone brute-forced uniformly over the character classes you used. Cheap, needs no training, and still useful when the model is off — but it **overrates** human passwords like `Password1!`. Prefer `label` / `strength_bits` when the model is on; treat `keyspace_bits` as a secondary “complexity” hint.

Default builds ship with an embedded model. You can skip it (`--no-model` / `skip_model`) and keep breach + `keyspace_bits` only. Full pipeline and research background: [docs/how-it-works.md](docs/how-it-works.md).

## Output

For each password, PSA returns a small JSON object. The fields most apps care about:

| Field | Meaning |
|-------|---------|
| `label` | `weak`, `fair`, `strong`, or `very_strong` — the main UI signal |
| `strength_bits` | Rough “how hard to guess?” score from the trained model (higher is harder) |
| `keyspace_bits` | Entropy / log₂ of the uniform brute-force keyspace (length × alphabet); easy to overrate `Password1!` |
| `breach` | Whether the password appears in Have I Been Pwned (online or offline) |
| `reasons` | Optional hints (e.g. sequential characters, looks like a UUID) |

Example:

```json
{
  "advisory": true,
  "aborted": false,
  "breach": { "pwned": false, "occurrences": 0, "source": "hibp_range" },
  "guess_number": 1234567.0,
  "strength_bits": 20.2,
  "keyspace_bits": 37.6,
  "label": "weak",
  "reasons": []
}
```

If the password is in a breach list, PSA stops early, sets `label` to `weak`, and sets `aborted` to `true` (scoring did not continue — the breach is enough for a warning).

**Rule of thumb:** show users **`label`** (and optionally breach messaging). Treat `keyspace_bits` as a secondary “complexity” hint, not as real-world strength.

## Usage

Same engine for the CLI and every language binding.

**`analyze` vs `analyze_offline`:** “Offline” means **no network** — score with the local model (and optional pattern / keyspace checks). It does **not** require a local HIBP database. Breach checking is separate: use `analyze` for the live HIBP API, or pass a local store (`--hibp-offline` / `hibp_offline_path`) if you want breach checks without the network. The language samples below use `analyze_offline` for a simple no-network demo.

**CLI**

```bash
cargo build -p psa-cli --release
./target/release/psa analyze-offline 'correcthorsebatterystaple'   # no network; no HIBP unless --hibp-offline
./target/release/psa analyze 'password'                            # live HIBP + scoring
./target/release/psa analyze-offline 'password' --hibp-offline data/hibp/ranges   # local HIBP store
```

On Windows without MSVC: `cargo +stable-x86_64-pc-windows-gnu build -p psa-cli --release`. More build options: [docs/install.md](docs/install.md).

**Python**

```python
from password_security_analyzer import analyze_offline
print(analyze_offline("password")["label"])
```

**Go**

```go
r, _ := psa.AnalyzeOffline("password", nil)
fmt.Println(r["label"])
```

**Java**

```java
System.out.println(PasswordSecurityAnalyzer.analyzeOffline("password", null).get("label"));
```

**Node.js**

```js
const { analyzeOffline } = require("@psa/password-security-analyzer-native");
console.log(analyzeOffline("password").label);
```

**.NET**

```csharp
using Psa;
var r = PasswordSecurityAnalyzer.AnalyzeOffline("password");
Console.WriteLine(r["label"]);
```

**Ruby**

```ruby
require "password_security_analyzer"
puts PasswordSecurityAnalyzer.analyze_offline("password")["label"]
```

**C++**

```cpp
#include "psa.hpp"
// JSON string — parse label as needed
std::cout << psa::analyze_offline("password") << "\n";
```

Packages and how to build the native library: [docs/bindings.md](docs/bindings.md). Browser/WASM: [`packages/psa-js`](packages/psa-js).

## Privacy

- Password analysis is local to your process.
- Online HIBP uses [k-anonymity](https://haveibeenpwned.com/API/v3#PwnedPasswords): the full password never leaves your app for that check. HIBP API uses first few characters of the SHA, not the password itself
- Prefer checking on blur/submit, not on every keystroke.

## When not to rely on it alone

- Account creation / login policy belongs on the server.
- Labels are heuristics for interactive UX, not a guarantee against offline GPU cracking.
- Very common leaked passwords are handled well; rarer mid-list leaks depend more on the statistical model. See [docs/leak-eval.md](docs/leak-eval.md) if you want to measure that yourself.

## More documentation

| Topic | Doc |
|-------|-----|
| Scoring design (pipeline, formulas, research background) | [docs/how-it-works.md](docs/how-it-works.md) |
| Build from source (CLI, WASM, Rust crate) | [docs/install.md](docs/install.md) |
| Language bindings / FFI | [docs/bindings.md](docs/bindings.md) |
| Training, offline HIBP, e2e, retrain | [docs/training.md](docs/training.md) |
| RockYou research evaluation | [docs/leak-eval.md](docs/leak-eval.md) |

## License

MIT
