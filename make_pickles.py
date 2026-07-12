#!/usr/bin/env python3
"""Chunk a text file of funded Bitcoin addresses (one per line) into pickle slices,
matching the repo's existing format: Python list[str], pickle protocol 4,
<= 1,000,000 addresses per file, named 00.pickle, 01.pickle, ...

Keeps only the address types whose payload is hash160(compressed pubkey) — the
value the collider generates — so a single generated hash160 is checked against
all of them for free:

  - P2PKH   ("1...")   legacy
  - P2WPKH  ("bc1q..." length 42) native SegWit v0

Everything else (P2SH "3...", P2WSH, Taproot "bc1p...") can never match and is
dropped here to keep the slices small. The Rust loader re-validates every address
by fully decoding it, so this filter only needs to be a cheap pre-pass.

Each slice stays ~35 MB, safely under GitHub's 50 MB/file limit.

Usage: python3 make_pickles.py <addresses.txt> <out_dir>
The input may be the full Loyce/Blockchair dump (all address types); this script
selects the ones that matter.
"""
import os
import pickle
import sys

CHUNK = 1_000_000
PROTO = 4


def keep(addr: str) -> bool:
    """Coarse filter for hash160(pubkey) address types."""
    if addr.startswith("1"):
        return True  # P2PKH
    # P2WPKH is bech32 v0 with a 20-byte program: "bc1q" + exactly 42 chars total.
    # (P2WSH is 62 chars, Taproot starts "bc1p" — both excluded.)
    if addr.startswith("bc1q") and len(addr) == 42:
        return True
    return False


def main():
    src, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    buf = []
    idx = 0
    total = 0
    seen = 0

    def flush(buf, idx):
        path = os.path.join(out_dir, f"{idx:02d}.pickle")
        with open(path, "wb") as f:
            pickle.dump(buf, f, protocol=PROTO)
        sz = os.path.getsize(path)
        print(f"wrote {path}  {len(buf):>8} addrs  {sz/1024/1024:.1f} MB")
        if sz > 49 * 1024 * 1024:
            print(f"  WARNING: {path} exceeds 49 MB", file=sys.stderr)

    with open(src, "r") as f:
        for line in f:
            addr = line.strip()
            if not addr:
                continue
            seen += 1
            if not keep(addr):
                continue
            buf.append(addr)
            total += 1
            if len(buf) == CHUNK:
                flush(buf, idx)
                idx += 1
                buf = []
    if buf:
        flush(buf, idx)
        idx += 1

    print(
        f"DONE: kept {total} P2PKH+P2WPKH of {seen} input addresses "
        f"across {idx} pickle files -> {out_dir}"
    )


if __name__ == "__main__":
    main()
