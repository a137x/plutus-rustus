#!/usr/bin/env python3
"""Chunk a text file of P2PKH addresses (one per line) into pickle slices,
matching the repo's existing format: Python list[str], pickle protocol 4,
<= 1,000,000 addresses per file, named 00.pickle, 01.pickle, ...

Each slice stays ~35 MB, safely under GitHub's 50 MB/file limit.
"""
import os
import pickle
import sys

CHUNK = 1_000_000
PROTO = 4


def main():
    src, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    buf = []
    idx = 0
    total = 0

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
            buf.append(addr)
            total += 1
            if len(buf) == CHUNK:
                flush(buf, idx)
                idx += 1
                buf = []
    if buf:
        flush(buf, idx)
        idx += 1

    print(f"DONE: {total} P2PKH addresses across {idx} pickle files -> {out_dir}")


if __name__ == "__main__":
    main()
