# Plutus-Rustus Bitcoin Brute Forcer

A Bitcoin wallet collider that brute forces random wallet addresses written in Rust.

This began as a port of [Plutus](https://github.com/Isaacdelly/Plutus) and has since been substantially optimised — see [Efficiency](#efficiency). On an Apple M3 Pro it now checks **~18 million keys/second** across all cores (**~2.85M single-thread**), using the same techniques that make [mattsta/Plutus](https://github.com/mattsta/Plutus) fast: a sequential elliptic-curve walk with batched (Montgomery) field inversion, and a SIMD `hash160`.

# Like This Project? Give It A Star

[![](https://img.shields.io/github/stars/a137x/plutus-rustus.svg)](https://github.com/a137x/plutus-rustus)

# Dependencies
Tested in `rustc 1.92.0`
For Rust dependencies see `Cargo.toml`. A C compiler is required at build time
(`cc`): the elliptic-curve hot path uses a small C shim (`csrc/`) over
[libsecp256k1](https://github.com/bitcoin-core/secp256k1) `v0.2.0`, pulled in as a
git submodule at `depend/secp256k1` (see [Installation](#installation)).
On aarch64 the SIMD `hash160` (`csrc/hash_neon.c`) is compiled in automatically;
other targets fall back to the `sha2`/`ripemd` crates.
Minimum <a href="#memory-consumption">RAM requirements</a>

# Installation

The libsecp256k1 C source is a git **submodule**, so clone recursively:

```
$ git clone --recursive https://github.com/a137x/plutus-rustus.git
```

Already cloned without `--recursive`? Pull the submodule in:

```
$ git submodule update --init --recursive
```

Compilation:
```
cargo rustc --release -- -C target-cpu=native
```

# Start

```
./target/release/plutus-rustus
```
## For linux users to run program in the background (dettach from ssh session):
```bash
bash start.sh & disown
```

By default one worker runs per logical core. Set `PLUTUS_THREADS=N` to cap the
worker count — e.g. `PLUTUS_THREADS=5 ./target/release/plutus-rustus` to use only
an M3 Pro's performance cores, or fewer to keep the machine responsive.

# Proof Of Concept

A private key is a secret number that allows Bitcoins to be spent. If a wallet has Bitcoins in it, then the private key will allow a person to control the wallet and spend whatever balance the wallet has. So this program attempts to find Bitcoin private keys that correlate to wallets with positive balances. However, because it is impossible to know which private keys control wallets with money and which private keys control empty wallets, we have to randomly look at every possible private key that exists and hope to find one that has a balance.

This program is essentially a brute forcing algorithm. It continuously generates Bitcoin private keys, converts them into their respective wallet addresses, then checks each address against an offline database of wallets that currently hold a balance. If a match is found, then the private key, public key and wallet address are saved to the text file `plutus.txt` on the user's hard drive. The ultimate goal is to find a wallet with a balance out of the 2<sup>160</sup> possible wallets in existence.

# How It Works

Each worker thread draws **one** random private key, then walks the key space sequentially by repeatedly adding the secp256k1 generator point `G` to the running public key. The walk is done in **batches of 512** so that the whole batch shares a single elliptic-curve field inversion instead of one per key (see [Efficiency](#efficiency)). Every public key is hashed to its 20-byte `hash160` — the core of a P2PKH address — via SHA-256 then RIPEMD-160; on aarch64 this uses the ARMv8 SHA-256 instructions and a 4-wide NEON RIPEMD-160. No Base58 encoding happens in the hot loop.

A pre-calculated database of P2PKH Bitcoin addresses with a positive balance is included in this project; it is decoded once to raw `hash160` bytes at startup. Each generated `hash160` is looked up in that set, and on a match the private key, public key and address are written to the text file `plutus.txt`.

This program utilizes multithreading through `std::thread` (one worker per logical core by default; see `PLUTUS_THREADS`) to make concurrent calculations.

# Efficiency

Every worker draws **one** random starting key and walks the key space
**sequentially** — the public key of `key+1` is the previous public key plus the
generator `G`, so no scalar multiplication is needed after the first key. Because
the secret behind `pub_n` is just `(start_secret + n) mod order`, any match is
fully reconstructable. On top of that, the two dominant hot-loop costs are attacked
with the techniques from [mattsta/Plutus](https://github.com/mattsta/Plutus),
implemented here in Rust over a small C shim:

**1. Batched elliptic-curve inversion.** Even a sequential walk still pays one
modular **field inversion per key** to bring each running point back to affine
coordinates for hashing — the single largest cost (~80% of the loop). Instead, a
batch of 512 points is accumulated in Jacobian coordinates (point additions, no
inversion) and converted to affine with **one** inversion for the whole batch
(Montgomery batch inversion). This runs on the **libsecp256k1** field arithmetic
(the `depend/secp256k1` submodule, called from `csrc/shim.c`) and is ~7x faster
than one `combine` per key.

**2. SIMD `hash160`.** `hash160 = RIPEMD-160(SHA-256(pubkey))`. On aarch64
(`csrc/hash_neon.c`) the SHA-256 uses the ARMv8 crypto instructions and RIPEMD-160
— which has no hardware instruction — is computed **4 keys at a time in NEON**,
~3.4x the `sha2`/`ripemd` crates. Other targets fall back to those crates
automatically.

Both paths are verified **bit-for-bit** against the reference implementations
(`cargo test`). The database is still decoded once to raw 20-byte `hash160` values
and matched directly — no Base58 in the loop.

Measured on an **Apple M3 Pro (5 performance + 6 efficiency cores)** with the
`JUL_12_2026` database (44,365,067 P2PKH + P2WPKH addresses):

| | single thread | 5 P-cores | all 11 cores |
|---|---|---|---|
| sequential `combine`, crate `hash160` | ~278k/s | — | ~3.15M/s |
| + batched inversion | ~1.48M/s | ~6.75M/s | ~10.5M/s |
| **+ SIMD `hash160`** | **~2.85M/s** | **~12.8M/s** | **~18.2M/s** |

That is roughly **10x single-thread** and **5.8x aggregate** over the previous
version. At **~2.56M keys/s per performance core** this matches mattsta's C
accelerator; the 11-core total is held back only by the M3's efficiency cores
running ~⅓ the speed of a performance core (set `PLUTUS_THREADS=5` to use the
performance cores alone). Database load is **~11s** (parallelised) and real memory
**~1.3 GB** — raw 20-byte `hash160` values for the P2PKH + P2WPKH funded set.

> Notes on techniques evaluated: a **pure-Rust `k256`** Montgomery batch was tried
> first and *lost* to libsecp256k1's `combine` (292k vs 476k keys/s single-thread)
> — the batch only wins on libsecp256k1-grade field multiplies, which is why the
> win came from batching *over libsecp256k1* rather than a different curve library.
> A **bloom pre-filter** gave no measurable gain (the tuned `HashSet` lookup is not
> the bottleneck, and P-core scaling stays ~linear), so it was not added.

To also cover uncompressed P2PKH addresses (funded keys exist under both encodings),
set `CHECK_UNCOMPRESSED = true` in `src/main.rs`: ~2x reachable database coverage
for ~10-15% throughput cost (the uncompressed path uses the scalar crate `hash160`).
# Database FAQ

An offline database of funded addresses is used to check generated addresses. The loader keeps both **P2PKH** (`1...`) and native SegWit **P2WPKH** (`bc1q...`) addresses, since both encode `hash160(compressed pubkey)` and are matched in the same lookup. The bundled snapshot (`JUL_12_2026`) holds `44,365,067` addresses — `21,273,320` P2PKH plus `23,091,747` P2WPKH — sourced from [Loyce Club](http://addresses.loyce.club/). See <a href="/database/">/database</a> for the format and refresh instructions.

# Expected Output

```bash
./target/release/plutus-rustus
```
```
Loaded "02.pickle"
Loaded "10.pickle"
Loaded "01.pickle"
...
Loaded 44358226 unique funded hash160s (P2PKH + P2WPKH) in 11.31s (0 other/invalid entries skipped)
Running on 11 worker thread(s)
checked       56623104 keys |   18822277 keys/s (last 3s) |   18822277 keys/s avg
checked      108658688 keys |   17338990 keys/s (last 3s) |   18081525 keys/s avg
checked      166985728 keys |   19396493 keys/s (last 3s) |   18520082 keys/s avg
checked      223215616 keys |   18722425 keys/s (last 3s) |   18570640 keys/s avg
...
```

Throughput is reported as an aggregate across all worker threads, refreshed every 3
seconds. The `avg` column stabilises around **~18 million keys/sec** on an 11-core
Apple M3 Pro (~2.85M single-thread).

If a wallet with a balance is found, then all necessary information about the wallet will be saved to the text file `plutus.txt`. An example is:

>4ef862ae89545a25cb75e1d56b19aef02fae6fdaea8f6cbeacf8e58e22edd480 // private key
>KysDe6HB1oPnUGCuXT88Pppqu1Td9WVDzgCYes9x4B1S5aL7bd2e // private key in Wallet Import Format (WIF)
>030bdfccb1fd2aac06cec7e688f944632a8ec33871cfaedfdd08e51f462a4e9532 // public key
>15x5ugXCVkzTbs24mG2bu1RkpshW3FTYW8 // P2PKH wallet address

# Memory Consumption
This program uses approximately `1.3` GB of real memory with the <a href="/database/">current database</a> (`44,365,067` addresses kept as raw 20-byte `hash160` values in a hash set). Memory consumption scales with database size and is independent of the number of threads (cores). Only `hash160(pubkey)` address types are kept — P2PKH (`1...`) and P2WPKH (`bc1q...`); P2SH (`3...`), P2WSH and Taproot (`bc1p...`) use a different payload the generator can never match, so they are excluded.

> Note: `ps`/`top` (RSS) may report ~1.9 GB for the process. That figure includes freed-but-not-yet-reclaimed pages left over from the parallel database load; the OS reclaims them on demand, so the true physical footprint is ~1.3 GB.


<a href="https://github.com/a137x/plutus-rustus/issues">Create an issue</a> so I can add more stuff to improve

# License
MIT License