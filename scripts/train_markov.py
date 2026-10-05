#!/usr/bin/env python3
"""Train order-4 Markov + Monte Carlo curve artifacts for psa-core.

Usage:
  python scripts/train_markov.py --wordlist data/seclists/train_combined.txt --out-dir models

Does not download breach dumps; pass a local wordlist (one password per line).
"""

from __future__ import annotations

import argparse
import math
import random
import struct
from collections import defaultdict
from pathlib import Path

BOS = "\u0001"
EOS = "\u0002"
UNK = "<unk>"
ORDER = 4
CTX = 3
MAGIC = b"PSA4"
MC_MAGIC = b"PSMC"
KNOWN_MAGIC = b"PSKN"
VERSION = 2  # Markov: u16 next_id + u16 saturated count; v1 was u32+u32
MC_VERSION = 1
KNOWN_VERSION = 1
U16_MAX = 65535


def pack_ctx(ids):
    return (ids[0] << 32) | (ids[1] << 16) | ids[2]


class Markov:
    def __init__(self, laplace: float = 0.01):
        self.vocab = [BOS, EOS, UNK]
        self.char_to_id = {BOS[0]: 0, EOS[0]: 1}
        self.unk_id = 2
        self.bos_id = 0
        self.eos_id = 1
        self.transitions = defaultdict(lambda: defaultdict(int))
        self.laplace = laplace

    def ensure(self, ch: str) -> int:
        if ch in self.char_to_id:
            return self.char_to_id[ch]
        i = len(self.vocab)
        self.vocab.append(ch)
        self.char_to_id[ch] = i
        return i

    def observe(self, password: str) -> None:
        ids = [self.bos_id] * CTX
        for ch in password:
            ids.append(self.ensure(ch))
        ids.append(self.eos_id)
        for i in range(len(ids) - CTX):
            ctx = ids[i : i + CTX]
            nxt = ids[i + CTX]
            self.transitions[pack_ctx(ctx)][nxt] += 1

    def resolve(self, ch: str) -> int:
        return self.char_to_id.get(ch, self.unk_id)

    def prob_next(self, ctx, nxt: int) -> float:
        key = pack_ctx(ctx)
        v = max(len(self.vocab), 1)
        total = float(sum(self.transitions[key].values())) if key in self.transitions else 0.0
        count = float(self.transitions[key].get(nxt, 0))
        return (count + self.laplace) / (total + self.laplace * v)

    def probability(self, password: str) -> float:
        ctx = [self.bos_id] * CTX
        p = 1.0
        for ch in password:
            i = self.resolve(ch)
            p *= self.prob_next(ctx, i)
            ctx = [ctx[1], ctx[2], i]
        p *= self.prob_next(ctx, self.eos_id)
        return max(p, 1e-300)

    def sample_next(self, ctx, rng: random.Random) -> int:
        key = pack_ctx(ctx)
        v = max(len(self.vocab), 1)
        total = float(sum(self.transitions[key].values())) if key in self.transitions else 0.0
        denom = total + self.laplace * v
        r = rng.random() * denom
        seen = self.transitions.get(key, {})
        for nid, count in seen.items():
            mass = count + self.laplace
            if r < mass:
                return nid
            r -= mass
        for nid in range(len(self.vocab)):
            if nid in seen:
                continue
            if r < self.laplace:
                return nid
            r -= self.laplace
        return self.eos_id

    def sample_password(self, max_len: int, rng: random.Random) -> str:
        ctx = [self.bos_id] * CTX
        out = []
        for _ in range(max_len):
            nxt = self.sample_next(ctx, rng)
            if nxt == self.eos_id:
                break
            if nxt in (self.bos_id, self.unk_id):
                continue
            out.append(self.vocab[nxt])
            ctx = [ctx[1], ctx[2], nxt]
        return "".join(out)

    def prune(
        self,
        min_count: int = 2,
        top_k: int | None = None,
    ) -> dict:
        """Drop rare transitions; optionally keep only top_k next-ids per context."""
        before_ctx = len(self.transitions)
        before_edges = sum(len(m) for m in self.transitions.values())
        new_t: dict = {}
        dropped_rare = 0
        dropped_topk = 0
        for key, mp in self.transitions.items():
            items = [(nid, c) for nid, c in mp.items() if c >= min_count]
            dropped_rare += len(mp) - len(items)
            if top_k is not None and len(items) > top_k:
                items.sort(key=lambda x: x[1], reverse=True)
                dropped_topk += len(items) - top_k
                items = items[:top_k]
            if items:
                new_t[key] = dict(items)
        self.transitions = defaultdict(lambda: defaultdict(int), new_t)
        after_edges = sum(len(m) for m in self.transitions.values())
        return {
            "contexts_before": before_ctx,
            "contexts_after": len(self.transitions),
            "edges_before": before_edges,
            "edges_after": after_edges,
            "dropped_rare": dropped_rare,
            "dropped_topk": dropped_topk,
        }

    def write(self, path: Path) -> None:
        if len(self.vocab) > U16_MAX:
            raise SystemExit(f"vocab too large for u16 ids: {len(self.vocab)}")
        with path.open("wb") as f:
            f.write(MAGIC)
            f.write(struct.pack("<I", VERSION))
            f.write(struct.pack("<I", ORDER))
            f.write(struct.pack("<d", self.laplace))
            f.write(struct.pack("<I", self.bos_id))
            f.write(struct.pack("<I", self.eos_id))
            f.write(struct.pack("<I", self.unk_id))
            f.write(struct.pack("<I", len(self.vocab)))
            for s in self.vocab:
                b = s.encode("utf-8")
                f.write(struct.pack("<I", len(b)))
                f.write(b)
            f.write(struct.pack("<I", len(self.transitions)))
            for key, mp in self.transitions.items():
                f.write(struct.pack("<Q", key))
                f.write(struct.pack("<I", len(mp)))
                for nid, count in mp.items():
                    c = min(int(count), U16_MAX)
                    f.write(struct.pack("<HH", int(nid), c))


def build_mc(model: Markov, n_unique: int, attempts: int, seed: int) -> tuple[list[float], list[float]]:
    rng = random.Random(seed)
    unique = {}
    for _ in range(attempts):
        if len(unique) >= n_unique:
            break
        pw = model.sample_password(24, rng)
        p = model.probability(pw)
        nlp = -math.log2(max(p, 1e-300))
        unique[nlp] = p
    items = sorted(unique.items(), key=lambda x: x[0])  # ascending nlp = desc p
    n = float(len(items)) or 1.0
    neg = []
    ranks = []
    cum = 0.0
    for nlp, p in items:
        cum += 1.0 / (n * max(p, 1e-300))
        neg.append(nlp)
        ranks.append(cum)
    return neg, ranks


def write_mc(path: Path, neg: list[float], ranks: list[float]) -> None:
    with path.open("wb") as f:
        f.write(MC_MAGIC)
        f.write(struct.pack("<I", MC_VERSION))
        f.write(struct.pack("<I", len(neg)))
        for nlp, rank in zip(neg, ranks):
            f.write(struct.pack("<d", nlp))
            f.write(struct.pack("<d", rank))


def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def ascii_lower(password: str) -> str:
    """Match Rust `str::to_ascii_lowercase` (A–Z only)."""
    return "".join(chr(ord(c) + 32) if 65 <= ord(c) <= 90 else c for c in password)


def hash_keys(password: str) -> list[int]:
    keys = [fnv1a64(password.encode("utf-8"))]
    lower = ascii_lower(password)
    if lower != password:
        keys.append(fnv1a64(lower.encode("utf-8")))
    return keys


def is_wordlist_comment(pw: str) -> bool:
    """True for editor-style comments (`# note`), not passwords like `#1bitch`."""
    if not pw.startswith("#"):
        return False
    return len(pw) == 1 or pw[1].isspace()


def write_known(path: Path, passwords, known_limit: int | None = None) -> int:
    """Frequency-order index: first occurrence = rank 1 (most common first).

    If known_limit is set, only the first N passwords (by training order) are indexed.
    That keeps embedded `known.bin` small when training on RockYou-scale corpora.
    """
    pairs: list[tuple[int, int]] = []
    seen: set[int] = set()
    rank = 0
    for pw in passwords:
        if not pw:
            continue
        rank += 1
        if known_limit is not None and rank > known_limit:
            break
        for key in hash_keys(pw):
            if key not in seen:
                seen.add(key)
                pairs.append((key, rank))
    pairs.sort(key=lambda x: x[0])
    collapsed: list[tuple[int, int]] = []
    for h, r in pairs:
        if collapsed and collapsed[-1][0] == h:
            collapsed[-1] = (h, min(collapsed[-1][1], r))
        else:
            collapsed.append((h, r))
    with path.open("wb") as f:
        f.write(KNOWN_MAGIC)
        f.write(struct.pack("<I", KNOWN_VERSION))
        f.write(struct.pack("<I", len(collapsed)))
        for h, r in collapsed:
            f.write(struct.pack("<Q", h))
            f.write(struct.pack("<I", r))
    return len(collapsed)


def iter_passwords(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for ln in fh:
            # Preserve spaces inside leak passwords; only drop the newline.
            pw = ln.rstrip("\r\n")
            if pw and not is_wordlist_comment(pw):
                yield pw


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wordlist", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, default=Path("models"))
    ap.add_argument("--laplace", type=float, default=0.01)
    ap.add_argument("--mc-unique", type=int, default=10000)
    ap.add_argument("--mc-attempts", type=int, default=80000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument(
        "--known-limit",
        type=int,
        default=500_000,
        help="Max passwords to store in known.bin (frequency-order head). 0 = all.",
    )
    ap.add_argument(
        "--max-train",
        type=int,
        default=None,
        help="Optional cap on passwords used to train Markov (default: all).",
    )
    ap.add_argument(
        "--prune-min-count",
        type=int,
        default=2,
        help="Drop transitions with count < N (0 disables pruning).",
    )
    ap.add_argument(
        "--prune-top-k",
        type=int,
        default=None,
        help="Optional: keep only top-K next characters per context.",
    )
    args = ap.parse_args()

    if not args.wordlist.exists():
        raise SystemExit(f"wordlist missing: {args.wordlist}")

    model = Markov(laplace=args.laplace)
    n_train = 0
    for pw in iter_passwords(args.wordlist):
        model.observe(pw)
        n_train += 1
        if args.max_train and n_train >= args.max_train:
            break
        if n_train % 1_000_000 == 0:
            print(f"  ...observed {n_train} passwords")

    if n_train == 0:
        raise SystemExit("wordlist empty")

    if args.prune_min_count > 0 or args.prune_top_k is not None:
        min_c = args.prune_min_count if args.prune_min_count > 0 else 1
        stats = model.prune(min_count=min_c, top_k=args.prune_top_k)
        print(
            "pruned transitions: "
            f"contexts {stats['contexts_before']}->{stats['contexts_after']}, "
            f"edges {stats['edges_before']}->{stats['edges_after']} "
            f"(rare={stats['dropped_rare']}, topk={stats['dropped_topk']})"
        )

    known_limit = None if args.known_limit == 0 else args.known_limit

    args.out_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.out_dir / "markov4.bin"
    mc_path = args.out_dir / "mc_curve.bin"
    known_path = args.out_dir / "known.bin"
    print(f"writing model v{VERSION} quantized u16 (vocab={len(model.vocab)})...")
    model.write(model_path)
    print("building Monte Carlo curve...")
    neg, ranks = build_mc(model, args.mc_unique, args.mc_attempts, args.seed)
    write_mc(mc_path, neg, ranks)
    print(f"writing known index (limit={known_limit})...")
    n_known = write_known(known_path, iter_passwords(args.wordlist), known_limit)
    print(f"trained on {n_train} passwords; vocab={len(model.vocab)}")
    print(
        f"wrote {model_path} ({model_path.stat().st_size} bytes), "
        f"{mc_path}, {known_path} (mc points={len(neg)}, known={n_known})"
    )


if __name__ == "__main__":
    main()
