# Database FAQ

This database is a list of Bitcoin addresses that currently hold a positive balance,
serialized into several `.pickle` files. Two address types are kept — **P2PKH**
(`1...`) and native SegWit **P2WPKH** (`bc1q...`) — because both encode
`hash160(compressed pubkey)`, which is exactly what the collider generates. A single
generated `hash160` is therefore checked against both types in one lookup, at no
extra cost in the hot loop.

### Source

The address set comes from [Loyce Club](http://addresses.loyce.club/)
(`Bitcoin_addresses_LATEST.txt.gz`), which republishes [Blockchair](https://blockchair.com/)'s
daily dump of every Bitcoin address with a balance. This is the same widely-used
source that current Plutus forks rely on; it replaces the original
`btcposbal2csv` method, which required running a full node and is effectively defunct.

Only P2PKH (`1...`) and P2WPKH (`bc1q...`, bech32 v0, 20-byte program) addresses are
kept — both are `hash160(pubkey)`. `3...` (P2SH), P2WSH, and Taproot (`bc1p...`)
addresses use a different payload the collider can never produce, so they are dropped
during preparation. This keeps the database smaller and the load fast.

### Format

Each file is a Python `list[str]` pickled with **protocol 4**, holding up to
`1,000,000` addresses (~35 MB each, safely under GitHub's 50 MB per-file limit).
At startup every file is decoded once to raw 20-byte `hash160` values and combined
into one in-memory set. The folder name is the snapshot date in `MON_DD_YYYY` format.

### How Many Addresses Does The Database Have?

The current snapshot (`JUL_11_2026`) holds **`21,273,320` funded P2PKH addresses**,
extracted from `56,827,685` total funded addresses of all types.

> Note: this bundled snapshot is currently **P2PKH-only** — it predates P2WPKH
> support. The loader now also matches P2WPKH (`bc1q...`) addresses, but they only
> take effect once the database is regenerated with the refresh steps below (the
> `grep` now keeps `bc1q...` too). Since much of today's funded BTC lives in bech32,
> refreshing meaningfully increases the reachable set at zero hot-loop cost.

### How To Refresh The Database

```bash
# 1. Download the latest funded-address list (~1.4 GB gz)
curl -O http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz

# 2. Extract P2PKH ("1...") and P2WPKH ("bc1q...") addresses (streamed).
#    make_pickles.py refines these (e.g. drops longer bc1q P2WSH), and the Rust
#    loader re-validates every address by fully decoding it.
gunzip -c Bitcoin_addresses_LATEST.txt.gz | grep -E '^(1|bc1q)' > funded.txt

# 3. Re-chunk into pickle slices into a new dated folder, then update
#    DB_VER in src/main.rs to match the folder name.
python3 make_pickles.py funded.txt database/MON_DD_YYYY
```
