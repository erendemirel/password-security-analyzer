# Password Security Analyzer

Helps your app tell users whether a password looks easy to guess and whether it has shown up in known breaches.

It runs on the device or in your backend, you embed a library (or CLI). There is no cloud service that receives the password.

**Try it:** [Test it here](https://password-security-analyzer-test.netlify.app) [![Netlify Status](https://api.netlify.com/api/v1/badges/0bfb54c3-5db6-458a-9607-a86ab6e62dfc/deploy-status)](https://app.netlify.com/projects/password-security-analyzer-test/deploys)

## How it works

Real attackers rarely try every possible string in alphabetical order. They try **common passwords and patterns first**, then rarer ones. PSA mirrors that with a few layers:

1. **Breach check**: If the password already appears in HIBP leaked passwords database, treat it as weak and stop. No model needed: a known leak is enough for a warning.
2. **Guessability model**: A Markov model trained on public password wordlists ([SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) common lists + [RockYou](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases)) estimates how “typical” the string looks; a Monte Carlo curve turns that into an estimated **guess number**, then `strength_bits = log2(guess_number)` and a `label`. This is the main “will this be guessed?” signal. (HIBP is used only for breach checks, not for training.)
3. **Pattern checks**: Some easy shapes (long alphabets, UUIDs, hex digests) look unlikely character-by-character, so the model can overrate them. Detectors can only push the label **weaker**, never stronger.
4. **Entropy (keyspace bits)**: Classic combinatorial size, roughly `length × log2(alphabet)` if someone brute-forced uniformly over the character classes you used. Cheap, needs no training, and still useful when the model is off, but it **overrates** human passwords like `Password1!`. Prefer `label` / `strength_bits` when the model is on; treat `keyspace_bits` as a secondary “complexity” hint.

Default builds ship with an embedded model. You can skip it (`--no-model` / `skip_model`) and keep breach + `keyspace_bits` only. Full pipeline and research background: [docs/how-it-works.md](docs/how-it-works.md).

## Output

For each password, PSA returns a small JSON object:

```jsonc
{
  "advisory": true,
  "aborted": false,              // true if scoring stopped early to save CPU time (e.g. known breach)
  "breach": {                    // Have I Been Pwned (online or offline store)
    "pwned": false,
    "occurrences": 0,
    "source": "hibp_range"
  },
  "guess_number": 1234567.0,
  "strength_bits": 20.2,         // Rough “how hard to guess?” score from the trained model (higher = harder)
  "keyspace_bits": 37.6,         // uniform brute-force entropy; easy to overrate Password1!
  "label": "weak",               // weak | fair | strong | very_strong — main UI signal
  "reasons": []                  // optional hints (sequential chars, looks like a UUID, …)
}
```

If the password is in a breach list, PSA stops early, sets `label` to `weak`, and sets `aborted` to `true` (scoring did not continue, the breach is enough for a warning).

**Rule of thumb:** show users **`label`** (and optionally breach messaging). Treat `keyspace_bits` as a secondary “complexity” hint, not as real-world strength.

## Installation

Install from the language registry (version tags `v*`). Building from a git clone is optional — see [docs/install.md](docs/install.md).

> [!WARNING]
> Installs are **large** (~15–22 MB per platform; the Ruby gem is ~90 MB). See [artifact sizes](docs/install.md#artifact-sizes).

```bash
# Python
pip install password-security-analyzer

# Node.js (server / native)
npm i @psa/password-security-analyzer-native

# Node.js / bundler (browser WASM)
npm i @psa/password-security-analyzer

# .NET
dotnet add package PasswordSecurityAnalyzer

# Java (Maven)
#   <dependency>
#     <groupId>io.github.erendemirel</groupId>
#     <artifactId>password-security-analyzer</artifactId>
#     <version>0.1.0</version>
#   </dependency>

# Ruby
gem install password_security_analyzer

# Go (cgo; prebuilt libs under lib/GOOS_GOARCH in the module)
go get github.com/erendemirel/password-security-analyzer/packages/psa-go@v0.1.0

# Rust
cargo add psa-core --git https://github.com/erendemirel/password-security-analyzer
# CLI binary: clone repo, then cargo build -p psa-cli --release

# C++ — psa.h / psa.hpp + shared lib from the GitHub Release for your tag
# https://github.com/erendemirel/password-security-analyzer/releases
```

Clone/build sizes: [docs/install.md](docs/install.md).

## Usage

Same engine for the CLI and every language binding. Call samples after [Installation](#installation):

> [!CAUTION]
> See [Security notice (server-side use)](#security-notice-server-side-use) first.

**CLI**

```bash
./target/release/psa analyze-offline 'correcthorsebatterystaple'   # no network; no HIBP unless --hibp-offline
./target/release/psa analyze 'password'                            # live HIBP + scoring
./target/release/psa analyze-offline 'password' --hibp-offline data/hibp/ranges   # local HIBP store
```

**Python**

```python
from password_security_analyzer import analyze_offline
print(analyze_offline("password")["label"])
```

**Go**

```go
import psa "github.com/erendemirel/password-security-analyzer/packages/psa-go"

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

> [!TIP]
> **`analyze` vs `analyze_offline`:** “Offline” means **no network** — score with the local model (and optional pattern / keyspace checks). It does **not** require a local HIBP database. Breach checking is separate: use `analyze` for the live HIBP API, or pass a local store (`--hibp-offline` / `hibp_offline_path`) if you want breach checks without the network. The samples below use `analyze_offline` for a simple no-network demo.

## Security notice (server-side use)

Scoring is **CPU heavy**. If you expose this from a backend without protection, an attacker can flood you with analyze requests and burn CPU, memory, or HIBP quota; a straightforward **DDoS** risk.

- Prefer running the meter **in the client** (WASM / native app) for UX; keep auth policy on the server.
- If you must call PSA on the server: **rate-limit** by IP and by account, set **timeouts**, cap **password length**, and do **not** offer an open, unauthenticated “score any string” API to the internet.
- Still enforce your own signup/login rules; PSA remains advisory only.

## Privacy

- Password analysis is local to your process.
- Online HIBP uses [k-anonymity](https://haveibeenpwned.com/API/v3#PwnedPasswords): the full password never leaves your app for that check. HIBP API uses first few characters of the SHA, not the password itself.
- Prefer checking on blur/submit, not on every keystroke.

## How it is verified

PSA is checked at a few layers (not a formal certification):

1. **Unit tests** — `cargo test -p psa-core` covers scoring helpers and core behavior in Rust.
2. **CLI end-to-end** — `e2e/run_e2e.py` runs the release `psa` binary on curated corpora (common passwords, SecLists samples, tricky patterns, offline HIBP aborts) and compares against a locked baseline so labels do not get unsafely stronger. See [e2e/README.md](e2e/README.md).
3. **Leak / research eval** — `scripts/eval_leak.py` scores RockYou (and controls) offline to check label mix and how `guess_number` tracks leak frequency; optional zxcvbn comparison. See [docs/leak-eval.md](docs/leak-eval.md).
4. **Language bindings** — each wrapper is smoke-tested against the same `psa-ffi` library (`analyze_offline("password")` → weak, plus a few pattern cases). Commands: [docs/bindings.md](docs/bindings.md).
5. **Interactive demo** — the [Netlify WASM demo](https://password-security-analyzer-test.netlify.app) exercises the browser build.

CI runs the Rust tests and a Python FFI smoke; the full e2e/leak suites are local (they need wordlists / HIBP data).

## When not to rely on it alone

- Account creation / login policy belongs on the server.
- Labels are heuristics for interactive UX, not a guarantee against offline GPU cracking.
- Very common leaked passwords are handled well; rarer mid-list leaks depend more on the statistical model. See [docs/leak-eval.md](docs/leak-eval.md) if you want to measure that yourself.

## More documentation

| Topic | Doc |
|-------|-----|
| How it works | [docs/how-it-works.md](docs/how-it-works.md) |
| Build from source | [docs/install.md](docs/install.md) |
| Bindings / FFI smoke | [docs/bindings.md](docs/bindings.md) |
| E2E CLI suites | [e2e/README.md](e2e/README.md) |
| Training | [docs/training.md](docs/training.md) |
| Leak eval | [docs/leak-eval.md](docs/leak-eval.md) |

## License

MIT
