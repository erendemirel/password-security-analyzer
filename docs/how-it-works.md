# How scoring works

This page is for readers who already know they want PSA and need the design details. For a product overview, start at the [root README](../README.md).

## Pipeline

Everything runs **in your process** (CLI, server library, or browser WASM). The password is never sent to a PSA server. The only optional network call is Have I Been Pwned (HIBP), which receives a **5-character SHA-1 prefix**, not the password ([k-anonymity](https://haveibeenpwned.com/API/v3#PwnedPasswords)).

```text
password
   │
   ├─► keyspace_bits          always
   │
   ├─► HIBP (optional)       if found in breaches → treat as weak and stop
   │
   └─► scoring model         unless disabled (skip_model / --no-model)
         │
         ├─ character Markov model → how “typical” the string looks
         ├─ Monte Carlo curve → estimated guess number
         ├─ known-password index → if common in training data, use that rank
         ├─ strength_bits = log2(guess_number)
         ├─ label from bit thresholds (prefers weaker when unsure)
         └─ pattern checks → may force the label down (e.g. abcd…, UUIDs)
```

### Breach check (HIBP)

- **Online:** hash with SHA-1, ask HIBP for the range matching the first five hex characters, look for the rest of the hash in the response ([Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)).
- **Offline:** same lookup against a local store from [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader).
- **If found:** analysis stops early. The result is labeled weak and marks that scoring was cut short (`aborted: true`). Breach evidence is enough for an advisory meter; there is no need to run the Markov model.

Practical notes: free, no API key; always send a descriptive `User-Agent`; HIBP padding is enabled; prefer checking on blur/submit, not every keystroke. Downloading an offline store: [training.md](training.md).

This matches common guidance such as [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) (check passwords against breached/known-bad lists; do not rely on composition rules alone) and the [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

### Keyspace bits

UI meters often report a combinatorial “entropy” estimate. PSA calls it `keyspace_bits` to make the assumption explicit:

\[
\text{keyspace\_bits} = L \cdot \log_2(|\Sigma|)
\]

where \(L\) is length and \(\Sigma\) is built from the character classes that appear. That is \(\log_2\) of the **uniform brute-force keyspace** — a standard information-theoretic formula when passwords are chosen uniformly from an alphabet (see [Password strength](https://en.wikipedia.org/wiki/Password_strength)). Research has long shown human-chosen passwords are *not* uniform, so this field is only a secondary hint.

How PSA computes it:

1. Note which classes appear: lowercase (+26), uppercase (+26), digits (+10), common symbols (+32), other Unicode (+1 per distinct character).
2. `base` = sum of those sizes.
3. `keyspace_bits = length × log2(base)` (same as `log2(base^length)`).

| Example | Classes | `base` | Length | ≈ `keyspace_bits` |
|---------|---------|--------|--------|------------------|
| `abcdef` | lower | 26 | 6 | 28.2 |
| `Ab1!` | all four | 94 | 4 | 26.3 |
| `correcthorsebatterystaple` | lower | 26 | 25 | 117.5 |

Useful for UI hints (“use more character types / length”) and when the model is turned off. **Not** a measure of real-world guessability: `Password1!` scores high here but is guessed quickly. When the model is on, trust **`label` / `strength_bits`** for “will this be guessed?”

| | `keyspace_bits` | `strength_bits` |
|--|----------------|-----------------|
| Assumes | Uniform brute force over observed classes | Ordered guessing under a leak-trained model |
| Needs model? | No | Yes (unless skipped) |
| Example `password` | ~37.6 | Very small |

### Guessability model

Threat model: an attacker who tries likely passwords first (as modern crackers do), not uniform brute force. That line of work trains a probability model \(P(\text{password})\) on real corpora (e.g. RockYou) and ranks guesses by likelihood.

Common approaches in the literature:

| Approach | Idea | Examples |
|----------|------|----------|
| **n-gram Markov** | \(P(c_i \mid\) previous characters\()\) — PSA uses order-4 | Narayanan & Shmatikov; Ma / Castelluccia et al. |
| **PCFG** | Templates (`word`+`digits`) + terminals | Weir et al., IEEE S&P 2009 |
| **Neural / GAN** | Generators that sample in likelihood order | Melicher et al.; Hitaj et al. (PassGAN) |

An engineering cousin of PSA’s Markov meter: [Microsoft Edge’s Markov password estimator](https://microsoftedge.github.io/edgevr/posts/Using-Markov-model-for-password-complexity-estimation-in-microsoft-edge/).

| File | Role |
|------|------|
| `markov4.bin` | Order-4 character Markov model. Estimates how probable the password is under patterns learned from training wordlists. Common patterns → high probability → guessed sooner. |
| `mc_curve.bin` | Precomputed map from that probability to an estimated **guess number**. Scoring interpolates the curve instead of enumerating the string space live. |
| `known.bin` | Compact index of the most common training passwords (default: top **500k** by frequency). If the password (or its ASCII-lower form) is in the index, the guess number is capped by that empirical rank. |

**Monte Carlo guess numbers.** Knowing \(P(\text{password})\) is not enough; defenders want *how many guesses* until that password. PSA follows Matteo Dell’Amico & Maurizio Filippone, **“Monte Carlo Strength Evaluation: Fast and Reliable Password Checking”** ([ACM CCS 2015](https://doi.org/10.1145/2810103.2813631), [PDF](https://www.dcs.gla.ac.uk/~maurizio/Publications/ccs15.pdf), [reference code](https://github.com/matteodellamico/montecarlopwd)): sample many passwords from the model, build a probability → rank curve offline, look up new passwords at score time. Related earlier work: Dell’Amico, Michiardi & Roudier, “Password strength: An empirical analysis” (INFOCOM 2010).

**Known-list rank.** Using a frequency-sorted leak head as “guessed early” is standard in evaluations and meters. PSA’s index can only **lower** the estimated guess number (safe bias). Measuring that against RockYou: [leak-eval.md](leak-eval.md).

Design choices that matter in practice:

- When signals disagree, the engine **prefers the weaker outcome** (known rank can only lower the guess number; pattern checks can only lower the label).
- Empty passwords are always weak.
- A HIBP hit skips the model entirely.
- Training can prune rare n-grams so model files stay a few megabytes (slightly less precision on rare sequences).

`strength_bits = log2(guess_number)`. Labels (prefer weaker when near a boundary):

| Label | `strength_bits` |
|-------|-----------------|
| `weak` | &lt; 28 (~2²⁸ guesses) |
| `fair` | 28–40 |
| `strong` | 40–56 |
| `very_strong` | ≥ 56 |

These thresholds are for an **online-style advisory meter**, not a claim about offline GPU cracking time.

You can disable the model (`--no-model` / `skip_model`) and keep HIBP + `keyspace_bits` only. See [training.md](training.md).

### Pattern checks (structural demotion)

Some strings look unlikely character-by-character (so Markov overrates them) but are still easy for humans or scripts: long alphabets, UUIDs, hex digests, etc. Detectors can only **lower** the label (usually to `weak`). This is heuristic engineering in the same family as pattern rules in meters like [zxcvbn](https://github.com/dropbox/zxcvbn) (Wheeler, USENIX 2016) — not a substitute for the trained model.

| Signal | Examples |
|--------|----------|
| `sequential_run` | `abcd…`, `987654` |
| `constant_gap` | `acegik…` |
| `tiled_fragment` | `abcabcabc` |
| `class_run` / `low_variety` | long digit blocks; long low-diversity strings |
| `whitespace_only` | spaces-only passwords |
| `structured_*` | UUID, MAC, IPv4, hex digests (32 / 40 / 64 hex) |

There is **no** hand-curated list of bad phrases. Common leaked / natural-language passwords are meant to be caught by **training data**. Coverage scales with the wordlist you train on.

### Limits

- Not an authorization gate; keep server-side policy, rate limits, and proper password hashing.
- Not calibrated to Hashcat/John guess order. [Leak evaluation](leak-eval.md) checks behavior on RockYou (label mix and correlation with leak frequency).
- Passwords that appear in leaks but outside the known-index head rely on Markov alone and can be overrated compared to exact membership.
