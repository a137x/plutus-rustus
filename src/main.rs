// Plutus-Rustus — Bitcoin P2PKH key-space collider.
//
// Strategy (see README "Efficiency"): instead of drawing a fresh random private
// key every iteration (one full elliptic-curve scalar multiplication each), every
// worker draws ONE random starting key and then walks sequentially using point
// addition — pub_{n+1} = pub_n + G — which is a single group operation. The secret
// that corresponds to pub_n is simply (start_secret + n) mod curve_order, so a hit
// is fully reconstructable. Addresses are matched as raw 20-byte hash160 values, so
// there is no Base58 encoding in the hot loop.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::{Address, Network, PrivateKey};

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const DB_VER: &str = "JUL_11_2026";

// Also derive and check the *uncompressed* P2PKH address for every key. Roughly
// doubles the reachable share of the database (funded keys exist under both
// encodings) at ~10-15% throughput cost. Off by default so the reported keys/sec
// is a clean 1-address-per-key figure; flip to `true` to maximise coverage.
const CHECK_UNCOMPRESSED: bool = false;

// Each worker sums keys locally and publishes to the shared counter in blocks of
// this size, so the atomic is touched rarely (no per-key cache-line contention).
const REPORT_BLOCK: u64 = 1 << 17; // 131_072

// ---------------------------------------------------------------------------
// Fast hasher for hash160 keys.
//
// A hash160 is already a uniformly-distributed 20-byte value, so there is no point
// running SipHash over it — the first 8 bytes are a perfect hash. hashbrown still
// compares the full 20 bytes on a probe, so this is exact, not probabilistic.
// ---------------------------------------------------------------------------
#[derive(Default)]
struct Hash160Hasher(u64);

impl Hasher for Hash160Hasher {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.0
    }
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        let mut buf = [0u8; 8];
        let n = bytes.len().min(8);
        buf[..n].copy_from_slice(&bytes[..n]);
        self.0 = self.0.rotate_left(5) ^ u64::from_le_bytes(buf);
    }
}

type Db = HashSet<[u8; 20], BuildHasherDefault<Hash160Hasher>>;

#[inline(always)]
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

fn main() {
    let db = Arc::new(load_database());
    let secp = Arc::new(Secp256k1::new());

    let num_cores = num_cpus::get();
    println!("Running on {} logical cores", num_cores);

    let counter = Arc::new(AtomicU64::new(0));

    for _ in 0..num_cores {
        let db = Arc::clone(&db);
        let secp = Arc::clone(&secp);
        let counter = Arc::clone(&counter);
        thread::spawn(move || process(&db, &secp, &counter));
    }

    // Aggregate throughput reporter (runs on the main thread forever).
    let start = Instant::now();
    let mut last_total = 0u64;
    let mut last_at = start;
    loop {
        thread::sleep(Duration::from_secs(3));
        let now = Instant::now();
        let total = counter.load(Ordering::Relaxed);
        let inst = (total - last_total) as f64 / (now - last_at).as_secs_f64();
        let avg = total as f64 / (now - start).as_secs_f64();
        println!(
            "checked {:>14} keys | {:>10.0} keys/s (last 3s) | {:>10.0} keys/s avg",
            total, inst, avg
        );
        last_total = total;
        last_at = now;
    }
}

// ---------------------------------------------------------------------------
// Hot loop: sequential public keys via point addition, matched on hash160.
// ---------------------------------------------------------------------------
fn process(db: &Db, secp: &Secp256k1<All>, counter: &AtomicU64) {
    let mut rng = rand::thread_rng();
    let g = generator(secp);

    loop {
        // Fresh random starting point for this walk.
        let start_secret = random_secret(&mut rng);
        let mut pubkey = PublicKey::from_secret_key(secp, &start_secret);
        let mut offset: u64 = 0;
        let mut since_report: u64 = 0;

        loop {
            // Compressed P2PKH.
            let hash = hash160(&pubkey.serialize());
            if db.contains(&hash) {
                report_hit(secp, &start_secret, offset, true);
            }

            // Optional uncompressed P2PKH (same key, different encoding).
            if CHECK_UNCOMPRESSED {
                let hash_u = hash160(&pubkey.serialize_uncompressed());
                if db.contains(&hash_u) {
                    report_hit(secp, &start_secret, offset, false);
                }
            }

            // Advance to the next key: pub += G  (i.e. secret += 1).
            match pubkey.combine(&g) {
                Ok(next) => pubkey = next,
                // Landed on the point at infinity (secret + offset == order):
                // ~2^-256 event; just start a new random walk.
                Err(_) => break,
            }
            offset += 1;

            since_report += 1;
            if since_report == REPORT_BLOCK {
                counter.fetch_add(REPORT_BLOCK, Ordering::Relaxed);
                since_report = 0;
            }
        }
    }
}

/// The secp256k1 generator point G as a `PublicKey` (1 · G), used as the per-step
/// addend so `combine` performs a plain point addition.
fn generator(secp: &Secp256k1<All>) -> PublicKey {
    let mut one = [0u8; 32];
    one[31] = 1;
    PublicKey::from_secret_key(secp, &SecretKey::from_slice(&one).unwrap())
}

/// Draw a valid random secret key (retries on the ~2^-128 chance of an invalid one).
fn random_secret(rng: &mut impl rand::RngCore) -> SecretKey {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

/// Reconstruct the matching key from (start_secret + offset) and persist it.
fn report_hit(secp: &Secp256k1<All>, start_secret: &SecretKey, offset: u64, compressed: bool) {
    let mut tweak = [0u8; 32];
    tweak[24..].copy_from_slice(&offset.to_be_bytes());
    let secret_key = start_secret
        .add_tweak(&Scalar::from_be_bytes(tweak).expect("offset < order"))
        .expect("valid secret");

    let mut private_key = PrivateKey::new(secret_key, Network::Bitcoin);
    private_key.compressed = compressed;
    let public_key = bitcoin::PublicKey::from_private_key(secp, &private_key);
    let address = Address::p2pkh(&public_key, Network::Bitcoin);

    let record = format!(
        "{}\n{}\n{}\n{}\n\n",
        secret_key.display_secret(),
        private_key.to_wif(),
        public_key,
        address
    );

    println!("!!! MATCH FOUND -> {address}\n{record}");
    if let Ok(mut file) = OpenOptions::new().append(true).open(found_file_path()) {
        let _ = file.write_all(record.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Database loading: decode Base58Check once, keep only P2PKH hash160 bytes.
// ---------------------------------------------------------------------------
fn load_database() -> Db {
    let dir = db_dir();
    let mut paths: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read database dir {dir}: {e}"))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| e == "pickle").unwrap_or(false))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no .pickle files found in {dir}");

    let timer = Instant::now();
    let num_threads = num_cpus::get().min(paths.len());

    // Round-robin the files across shards so each shard does similar work.
    let mut shards: Vec<Vec<_>> = (0..num_threads).map(|_| Vec::new()).collect();
    for (i, p) in paths.into_iter().enumerate() {
        shards[i % num_threads].push(p);
    }

    let mut skipped = 0u64;
    let mut db: Db = HashSet::with_capacity_and_hasher(26_000_000, Default::default());

    let shard_results: Vec<(Vec<[u8; 20]>, u64)> = thread::scope(|s| {
        let handles: Vec<_> = shards
            .into_iter()
            .map(|shard| s.spawn(move || load_shard(shard)))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    for (hashes, shard_skipped) in shard_results {
        skipped += shard_skipped;
        db.extend(hashes);
    }

    println!(
        "Loaded {} unique P2PKH addresses in {:.2?} ({} non-P2PKH/invalid entries skipped)",
        db.len(),
        timer.elapsed(),
        skipped
    );
    db
}

fn load_shard(paths: Vec<std::path::PathBuf>) -> (Vec<[u8; 20]>, u64) {
    let mut out = Vec::new();
    let mut skipped = 0u64;
    for path in paths {
        let mut bytes = Vec::new();
        File::open(&path)
            .and_then(|mut f| f.read_to_end(&mut bytes))
            .unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let addresses: Vec<String> =
            serde_pickle::from_slice(&bytes, Default::default()).expect("couldn't load pickle");

        for addr in &addresses {
            match bitcoin::base58::decode_check(addr) {
                // version 0x00 + 20-byte hash160 == P2PKH ("1..." addresses)
                Ok(raw) if raw.len() == 21 && raw[0] == 0x00 => {
                    let mut h = [0u8; 20];
                    h.copy_from_slice(&raw[1..21]);
                    out.push(h);
                }
                _ => skipped += 1,
            }
        }
        println!("Loaded {:?}", path.file_name().unwrap_or_default());
    }
    (out, skipped)
}

fn db_dir() -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push("database");
    path.push(DB_VER);
    path.to_str().unwrap().to_string()
}

fn found_file_path() -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push("plutus.txt");
    path.to_str().unwrap().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_from_u8(last: u8) -> SecretKey {
        let mut b = [0u8; 32];
        b[31] = last;
        SecretKey::from_slice(&b).unwrap()
    }

    // Known test vectors for private key == 1.
    #[test]
    fn derivation_matches_known_vectors() {
        let secp = Secp256k1::new();
        let sk = secret_from_u8(1);

        let mut pk_c = PrivateKey::new(sk, Network::Bitcoin);
        pk_c.compressed = true;
        let addr_c = Address::p2pkh(&bitcoin::PublicKey::from_private_key(&secp, &pk_c), Network::Bitcoin);
        assert_eq!(addr_c.to_string(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");

        let mut pk_u = PrivateKey::new(sk, Network::Bitcoin);
        pk_u.compressed = false;
        let addr_u = Address::p2pkh(&bitcoin::PublicKey::from_private_key(&secp, &pk_u), Network::Bitcoin);
        assert_eq!(addr_u.to_string(), "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
    }

    // The hot-loop hash160 path must produce the exact bytes stored from the DB decode
    // path, or a funded key would never match.
    #[test]
    fn hotloop_hash160_matches_db_decode() {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &secret_from_u8(1));
        let raw = bitcoin::base58::decode_check("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").unwrap();
        assert_eq!(raw[0], 0x00);
        assert_eq!(&hash160(&pk.serialize())[..], &raw[1..21]);
    }

    // Walking with `combine` (pub += G) must stay in lock-step with (start_secret + offset),
    // so report_hit reconstructs the correct private key.
    #[test]
    fn sequential_walk_reconstructs_secret() {
        let secp = Secp256k1::new();
        let g = generator(&secp);
        let start = secret_from_u8(123);
        let mut pk = PublicKey::from_secret_key(&secp, &start);
        for offset in 0..2000u64 {
            let mut tweak = [0u8; 32];
            tweak[24..].copy_from_slice(&offset.to_be_bytes());
            let sk = start.add_tweak(&Scalar::from_be_bytes(tweak).unwrap()).unwrap();
            assert_eq!(pk, PublicKey::from_secret_key(&secp, &sk), "offset {offset}");
            pk = pk.combine(&g).unwrap();
        }
    }
}
