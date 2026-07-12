# Plutus-Rustus Bitcoin Brute Forcer

A Bitcoin wallet collider that brute forces random wallet addresses written in Rust.

This began as a port of [Plutus](https://github.com/Isaacdelly/Plutus) and has since been substantially optimised — see [Efficiency](#efficiency) for the ~7.7x speedup over the initial port (and far larger gains over the Python original).

# Like This Project? Give It A Star

[![](https://img.shields.io/github/stars/a137x/plutus-rustus.svg)](https://github.com/a137x/plutus-rustus)

# Dependencies
Tested in `rustc 1.92.0`
For dependencies see `Cargo.toml`
Minimum <a href="#memory-consumption">RAM requirements</a>

# Installation

```
$ git clone https://github.com/a137x/plutus-rustus.git
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

# Proof Of Concept

A private key is a secret number that allows Bitcoins to be spent. If a wallet has Bitcoins in it, then the private key will allow a person to control the wallet and spend whatever balance the wallet has. So this program attempts to find Bitcoin private keys that correlate to wallets with positive balances. However, because it is impossible to know which private keys control wallets with money and which private keys control empty wallets, we have to randomly look at every possible private key that exists and hope to find one that has a balance.

This program is essentially a brute forcing algorithm. It continuously generates Bitcoin private keys, converts them into their respective wallet addresses, then checks each address against an offline database of wallets that currently hold a balance. If a match is found, then the private key, public key and wallet address are saved to the text file `plutus.txt` on the user's hard drive. The ultimate goal is to find a wallet with a balance out of the 2<sup>160</sup> possible wallets in existence.

# How It Works

Each worker thread draws **one** random private key, then walks the key space sequentially by repeatedly adding the secp256k1 generator point `G` to the running public key (see [Efficiency](#efficiency)). Every public key is hashed to its 20-byte `hash160` — the core of a P2PKH address — using the [`secp256k1`](https://docs.rs/secp256k1), [`sha2`](https://docs.rs/sha2) and [`ripemd`](https://docs.rs/ripemd) crates. No Base58 encoding happens in the hot loop.

A pre-calculated database of P2PKH Bitcoin addresses with a positive balance is included in this project; it is decoded once to raw `hash160` bytes at startup. Each generated `hash160` is looked up in that set, and on a match the private key, public key and address are written to the text file `plutus.txt`.

This program utilizes multithreading through `std::thread` (one worker per logical core) to make concurrent calculations.

# Efficiency

Rather than drawing a fresh random private key every iteration — which costs one full
elliptic-curve scalar multiplication each — every worker draws **one** random starting
key and then walks the key space **sequentially** using elliptic-curve point addition:

```
pub_{n+1} = pub_n + G          (secret_{n+1} = secret_n + 1)
```

Point addition is a single group operation, so this is dramatically cheaper than a
scalar multiplication per key. Because the secret behind `pub_n` is just
`(start_secret + n) mod order`, any match is fully reconstructable.

Two further changes remove overhead from the hot loop:

- **No Base58 in the loop.** The database is decoded once to raw 20-byte `hash160`
  values and generated keys are matched as `hash160` bytes directly — no Base58Check
  encoding per key.
- **secp256k1 context created once** (it was previously rebuilt every iteration),
  a compact `HashSet<[u8; 20]>` with a hash tuned for uniform hash160 keys, and
  parallel database loading.

Measured on an **Apple M3 Pro (11 logical cores)** with the `JUL_11_2026` database
(21,273,320 P2PKH addresses):

| | keys/sec (aggregate) | per core |
|---|---|---|
| previous (random key per iter, Base58, context-in-loop) | ~407,000 | ~37,000 |
| current (sequential point addition, hash160 match) | **~3,150,000** | ~285,000 |

That is roughly a **7.7x** speedup. Database load time also dropped from ~15s to
**~6s** (parallelised), and real memory from ~3.3 GB to **~0.7 GB** — only P2PKH
`hash160` bytes are kept instead of full Base58 address strings.

> Note on techniques evaluated: a Montgomery batch-inversion approach (`k256`
> projective points, the "textbook" fast path) was benchmarked and lost to
> libsecp256k1's `combine` on this hardware (292k vs 476k keys/s single-thread),
> because libsecp256k1's hand-tuned field arithmetic outweighs the saved inversions.
> A bloom pre-filter was also benchmarked and gave no measurable gain (the tuned
> `HashSet` lookup already costs only ~7%), so it was not added.

To also cover uncompressed P2PKH addresses (funded keys exist under both encodings),
set `CHECK_UNCOMPRESSED = true` in `src/main.rs`: ~2x reachable database coverage
for ~10-15% throughput cost.
# Database FAQ

An offline database of funded P2PKH addresses is used to check generated addresses. The bundled snapshot (`JUL_11_2026`) holds `21,273,320` currently-funded P2PKH addresses sourced from [Loyce Club](http://addresses.loyce.club/). See <a href="/database/">/database</a> for the format and refresh instructions.

# Expected Output

```bash
./target/release/plutus-rustus
```
```
Loaded "02.pickle"
Loaded "10.pickle"
Loaded "01.pickle"
...
Loaded 21273320 unique P2PKH addresses in 6.03s (0 non-P2PKH/invalid entries skipped)
Running on 11 logical cores
checked        8781824 keys |    2920999 keys/s (last 3s) |    2920999 keys/s avg
checked       19005440 keys |    3403059 keys/s (last 3s) |    3161941 keys/s avg
checked       28704768 keys |    3227704 keys/s (last 3s) |    3183860 keys/s avg
checked       38141952 keys |    3141693 keys/s (last 3s) |    3173322 keys/s avg
...
```

Throughput is reported as an aggregate across all worker threads, refreshed every 3
seconds. The `avg` column stabilises around **~3.15 million keys/sec** on an 11-core
Apple M3 Pro.

If a wallet with a balance is found, then all necessary information about the wallet will be saved to the text file `plutus.txt`. An example is:

>4ef862ae89545a25cb75e1d56b19aef02fae6fdaea8f6cbeacf8e58e22edd480 // private key
>KysDe6HB1oPnUGCuXT88Pppqu1Td9WVDzgCYes9x4B1S5aL7bd2e // private key in Wallet Import Format (WIF)
>030bdfccb1fd2aac06cec7e688f944632a8ec33871cfaedfdd08e51f462a4e9532 // public key
>15x5ugXCVkzTbs24mG2bu1RkpshW3FTYW8 // P2PKH wallet address

# Memory Consumption
This program uses approximately `0.7` GB of real memory (~670 MB, as reported by Activity Monitor's *Real Memory Size*) with the <a href="/database/">current database</a> (`21,273,320` P2PKH addresses kept as raw 20-byte `hash160` values). Memory consumption depends on database size and is independent of the number of threads (cores). Non-P2PKH entries (`3...` P2SH, `bc1...` bech32) are excluded from the database entirely, since a P2PKH generator can never match them.

> Note: `ps`/`top` (RSS) may report ~1.4 GB for the process. That figure includes freed-but-not-yet-reclaimed pages left over from the parallel database load; the OS reclaims them on demand, so the true physical footprint is ~670 MB.


<a href="https://github.com/a137x/plutus-rustus/issues">Create an issue</a> so I can add more stuff to improve

# License
MIT License