# Model artifacts

- `markov4.bin` — order-4 character Markov model (PSA4 **v2**: pruned + u16-quantized transitions)
- `mc_curve.bin` — Monte Carlo guess-rank curve paired with the model
- `known.bin` — FNV-1a hashes of training passwords with empirical ranks

Regenerate from a local wordlist (do not commit raw breach dumps):

```bash
python scripts/train_markov.py --wordlist data/seclists/train_combined.txt --out-dir models \
  --prune-min-count 2 --known-limit 500000
```

Size knobs:

- `--prune-min-count N` — drop transitions seen fewer than N times (default 2)
- `--prune-top-k K` — keep only the K most frequent next-chars per context
- Counts are stored as `u16` (saturated); next-ids as `u16` (v2 format)

These files are embedded into `psa-core` when the `embedded-model` feature is enabled (default).

Build without them:

```bash
cargo build -p psa-core --no-default-features --features native-http
```

Then either use `--no-model` / `skip_model`, or load artifacts at runtime with `ScoringEngine::from_paths`.
