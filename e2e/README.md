# E2E tests (real CLI)

1. Build the CLI:
   ```bash
   cargo +stable-x86_64-pc-windows-gnu build -p psa-cli --release
   ```
2. Refresh SecLists + offline HIBP + model:
   ```bash
   python scripts/download_seclists.py
   python scripts/download_hibp.py --e2e
   python scripts/train_markov.py --wordlist data/seclists/train_combined.txt --out-dir models
   cargo +stable-x86_64-pc-windows-gnu build -p psa-cli --release
   ```
3. Run:
   ```bash
   python e2e/run_e2e.py
   ```
4. On a green run, lock the baseline for trend detection:
   ```bash
   python e2e/run_e2e.py --update-baseline
   ```

## Artifacts

| File | Purpose |
|------|---------|
| `e2e/results/<timestamp>.json` | Full snapshot of every run |
| `e2e/results/latest.json` | Most recent run |
| `e2e/results/baseline.json` | Locked “good” run; later runs fail if labels get *stronger* unsafely or cases start failing |
| `e2e/results/eval_*.json` / `eval_latest.json` | RockYou leak eval reports; see [docs/leak-eval.md](../docs/leak-eval.md) |
| `e2e/corpus_seclists.json` | Sampled from [SecLists Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords) via `scripts/download_seclists.py` |
| `e2e/corpus_hibp.json` | Offline HIBP pwned aborts; needs `data/hibp/ranges` from `scripts/download_hibp.py` |
| `e2e/corpus_keyspace.json` | Short “random-looking” Markov overrate / keyspace-cap guards |
| `e2e/corpus_structure.json` | Dates, phones, base64, keyboard-walk demotion |

## Corpus notes

Includes cases from the [Microsoft Edge Markov password estimator article](https://microsoftedge.github.io/edgevr/posts/Using-Markov-model-for-password-complexity-estimation-in-microsoft-edge/), SecLists samples, and offline [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)-compatible HIBP checks.

Every scored case also enforces `strength_bits ≤ keyspace_bits`. Remaining gaps: mid-list leaks outside `known.bin` (see [leak-eval.md](../docs/leak-eval.md)); full e2e/HIBP not in CI; keyboard walks assume QWERTY.

## Leak evaluation (ops / research)

Regression e2e above checks curated fixtures. For how PSA labels common RockYou passwords and how guess numbers track leak frequency, see [docs/leak-eval.md](../docs/leak-eval.md):

```bash
python scripts/eval_leak.py
python scripts/eval_leak.py --with-zxcvbn   # optional comparison to zxcvbn
```

Requires `data/seclists/rockyou.txt`. Report-only (does not fail CI).
