# Training and model options

## Optional training-dependent scoring

| Mode | What runs |
|------|-----------|
| Default build | HIBP + keyspace bits + embedded Markov/MC |
| `--no-model` / `skip_model: true` | HIBP + keyspace bits only |
| Build without `embedded-model` | Same as no-model unless you pass a `ScoringEngine` loaded from disk |

```bash
# Keyspace bits (+ optional HIBP) only — no guess_number / label
psa analyze-offline 'secret' --no-model
psa analyze 'secret' --no-model --skip-breach

# Is the default model compiled in?
psa model-info
```

Slim Rust dependency (no embedded `models/*.bin`):

```toml
psa-core = { path = "crates/psa-core", default-features = false, features = ["native-http"] }
```

You can still load a model at runtime with `ScoringEngine::from_paths(...)`.

## SecLists training + HIBP offline + e2e

**Markov training** needs plaintext wordlists ([SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords)). RockYou (optional below) is the classic frequency-sorted research corpus also used in work such as the [Edge Markov estimator](https://microsoftedge.github.io/edgevr/posts/Using-Markov-model-for-password-complexity-estimation-in-microsoft-edge/).

**Breach checks** can use the live k-anonymity API or an offline SHA-1 store from
[PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader) (hashes only — not for training). That supports the usual “reject known-breached passwords” guidance (e.g. NIST SP 800-63B); scoring design details live in [how-it-works.md](how-it-works.md).

```bash
# Curated common lists (~80k)
python scripts/download_seclists.py

# Include RockYou (~14M, frequency-sorted; Edge/RockYou research corpus)
python scripts/download_seclists.py --rockyou

python scripts/download_hibp.py --e2e
python scripts/train_markov.py --wordlist data/seclists/train_combined.txt --out-dir models --known-limit 500000 --prune-min-count 2
cargo +stable-x86_64-pc-windows-gnu build -p psa-cli --release
python e2e/run_e2e.py --update-baseline
```

`--known-limit` caps the embedded membership index (default 500k) so RockYou-scale training does not balloon `known.bin`. Markov still trains on the full combined wordlist. `--prune-min-count 2` drops singleton transitions; the model file is **PSA4 v2** (u16 ids + u16 saturated counts).

`e2e/run_e2e.py` loads `corpus.json`, `corpus_seclists.json`, `corpus_hibp.json`, and `corpus_tricky.json`.

```bash
# Local HIBP without network
psa analyze-offline 'password' --hibp-offline data/hibp/ranges
psa check-pwned 'password' --hibp-offline data/hibp/ranges
```

## Retrain the model

Default artifacts live in `models/` (trained from SecLists + optional RockYou via `data/seclists/train_combined.txt`). For a custom model, point at a larger **local** public wordlist (do not commit raw breach dumps):

```bash
python scripts/train_markov.py --wordlist path/to/wordlist.txt --out-dir models
```

Then rebuild so `include_bytes!` picks up the new files.
