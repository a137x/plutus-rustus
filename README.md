# Plutus-Rustus Bitcoin Brute Forcer

A Bitcoin wallet collider that brute forces random wallet addresses written in Rust.

This is a straight port of [Plutus](https://github.com/Isaacdelly/Plutus) with significant perfomance gains over python counterpart.

# Like This Project? Give It A Star

[![](https://img.shields.io/github/stars/a137x/plutus-rustus.svg)](https://github.com/a137x/plutus-rustus)

# Dependencies
Tested in `rustc 1.61.0 (fe5b13d68 2022-05-18)`
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

# Proof Of Concept

A private key is a secret number that allows Bitcoins to be spent. If a wallet has Bitcoins in it, then the private key will allow a person to control the wallet and spend whatever balance the wallet has. So this program attempts to find Bitcoin private keys that correlate to wallets with positive balances. However, because it is impossible to know which private keys control wallets with money and which private keys control empty wallets, we have to randomly look at every possible private key that exists and hope to find one that has a balance.

This program is essentially a brute forcing algorithm. It continuously generates random Bitcoin private keys, converts the private keys into their respective wallet addresses, then checks the balance of the addresses. If a wallet with a balance is found, then the private key, public key and wallet address are saved to the text file `plutus.txt` on the user's hard drive. The ultimate goal is to randomly find a wallet with a balance out of the 2<sup>160</sup> possible wallets in existence. 

# How It Works

Private keys are generated randomly with a help of bitcoin rust [library]( https://docs.rs/crate/bitcoin/latest).

The private keys are converted into their respective public keys. Then the public keys are converted into their Bitcoin wallet addresses.

A pre-calculated database of every P2PKH Bitcoin address with a positive balance is included in this project. The generated address is searched within the database, and if it is found that the address has a balance, then the private key, public key and wallet address are saved to the text file `plutus.txt` on the user's hard drive.

This program also utilizes multithreading through `tokio::task` in order to make concurrent calculations.

# Efficiency


# Database FAQ

An offline database is used to find the balance of generated Bitcoin addresses. Visit <a href="/database/">/database</a> for information.

# Expected Output

```bash
./target/release/plutus-rustus 
```   
```          
Loading pickle slice from file DirEntry("/plutus-rustus/database/MAR_15_2021/02.pickle")
Database size 1000000 addresses.
Loading pickle slice from file DirEntry("/plutus-rustus/database/MAR_15_2021/00.pickle")
Database size 2000000 addresses.
Loading pickle slice from file DirEntry("/plutus-rustus/database/MAR_15_2021/01.pickle")
Database size 3000000 addresses.
...
Load of pickle files completed in 7.74s, database size: 33165253
Running on 4 cores
Core ThreadId(10) started
Core ThreadId(11) started
Core ThreadId(12) started
Core ThreadId(13) started
Core ThreadId(13) checked 10000 addresses in 0.95, iter/sec: 10581.981747510054
Core ThreadId(12) checked 10000 addresses in 0.95, iter/sec: 10524.61153358878
Core ThreadId(11) checked 10000 addresses in 0.96, iter/sec: 10444.270972762719
Core ThreadId(10) checked 10000 addresses in 0.96, iter/sec: 10363.59450488973
...
```

If a wallet with a balance is found, then all necessary information about the wallet will be saved to the text file `plutus.txt`. An example is:

>4ef862ae89545a25cb75e1d56b19aef02fae6fdaea8f6cbeacf8e58e22edd480 // private key
>KysDe6HB1oPnUGCuXT88Pppqu1Td9WVDzgCYes9x4B1S5aL7bd2e // hex private key in Wallet Import Format
>030bdfccb1fd2aac06cec7e688f944632a8ec33871cfaedfdd08e51f462a4e9532 // public key
>15x5ugXCVkzTbs24mG2bu1RkpshW3FTYW8 // P2PKH wallet address

# Memory Consumption



<a href="https://github.com/a137x/plutus-rustus/issues">Create an issue</a> so I can add more stuff to improve
