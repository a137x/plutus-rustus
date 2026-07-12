# Database FAQ

This database is a list of Bitcoin **P2PKH** addresses (`1...`) that currently hold a
positive balance, serialized into several `.pickle` files.

### Source

The address set comes from [Loyce Club](http://addresses.loyce.club/)
(`Bitcoin_addresses_LATEST.txt.gz`), which republishes [Blockchair](https://blockchair.com/)'s
daily dump of every Bitcoin address with a balance. This is the same widely-used
source that current Plutus forks rely on; it replaces the original
`btcposbal2csv` method, which required running a full node and is effectively defunct.

Only P2PKH (`1...`) addresses are kept. The collider derives P2PKH addresses, so
`3...` (P2SH) and `bc1...` (bech32/SegWit) entries can never match and are dropped
during preparation — this keeps the database small and the load fast.

### Format

Each file is a Python `list[str]` pickled with **protocol 4**, holding up to
`1,000,000` addresses (~35 MB each, safely under GitHub's 50 MB per-file limit).
At startup every file is decoded once to raw 20-byte `hash160` values and combined
into one in-memory set. The folder name is the snapshot date in `MON_DD_YYYY` format.

### How Many Addresses Does The Database Have?

The current snapshot (`JUL_11_2026`) holds **`21,273,320` funded P2PKH addresses**,
extracted from `56,827,685` total funded addresses of all types.

> Note: this is *fewer* P2PKH addresses than the old `MAR_15_2021` set
> (~24.9M), because since 2021 many legacy `1...` addresses were spent/emptied and
> the ecosystem shifted to bech32. These 21.3M are addresses funded *today*, so the
> data is fresher and higher quality even though the count is smaller.

### How To Refresh The Database

```bash
# 1. Download the latest funded-address list (~1.4 GB gz)
curl -O http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz

# 2. Extract only P2PKH ("1...") addresses (streamed, no full 6 GB on disk)
gunzip -c Bitcoin_addresses_LATEST.txt.gz | grep '^1' > p2pkh.txt

# 3. Re-chunk into pickle slices into a new dated folder, then update
#    DB_VER in src/main.rs to match the folder name.
python3 make_pickles.py p2pkh.txt database/MON_DD_YYYY
```
