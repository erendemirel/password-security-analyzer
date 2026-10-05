# Leak evaluation

Optional research script (not part of CI). It scores real leaked passwords from RockYou and a few control sets with `psa analyze-offline --batch`, so you can see how the analyzer behaves on known-weak and should-be-strong material.

RockYou-style corpora are the usual benchmark in password research for “how common is this string in real leaks?” The script does **not** simulate Hashcat/John attack order; it checks PSA’s labels and guess numbers against leak frequency and optional third-party meters.

```bash
# Needs data/seclists/rockyou.txt and a release CLI build
python scripts/eval_leak.py
python scripts/eval_leak.py --limit 10000 --controls 200
python scripts/eval_leak.py --with-zxcvbn   # pip install zxcvbn
```

JSON reports go to `e2e/results/eval_*.json` and `eval_latest.json`. The script prints three kinds of summary:

- **Label mix** — how often PSA says weak / fair / strong / very_strong on the most common RockYou passwords, versus random strings and passphrase-style controls. Common leaks should skew weak; random/passphrase controls should skew stronger.
- **zxcvbn comparison** (optional) — same RockYou sample scored with Dropbox [zxcvbn](https://github.com/dropbox/zxcvbn) (Daniel Wheeler, USENIX 2016; scores 0–4). Different algorithm from PSA’s Markov + Monte Carlo path, but a common industry baseline.
- **Rank correlation** — for passwords that appear *after* the embedded known-list head (default: ranks above 500k), how well PSA’s `guess_number` tracks how common the password was in the leak (Spearman on log scales). Higher correlation means rarer leak passwords get larger guess numbers.

That correlation measures **how popular the password was in the leak**, not how a GPU cracker would order guesses. Scoring design background: [how-it-works.md](how-it-works.md).
