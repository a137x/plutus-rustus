// Plutus-Rustus — Bitcoin P2PKH key-space collider.
//
// Strategy (see README "Efficiency"): instead of drawing a fresh random private
// key every iteration (one full elliptic-curve scalar multiplication each), every
// worker draws ONE random starting key and then walks sequentially — the public
// key of key+1 is key's public key plus the generator G. The secret behind the
// n-th key is simply (start_secret + n) mod curve_order, so any hit is fully
// reconstructable, and addresses are matched as raw 20-byte hash160 values (no
// Base58 in the hot loop).
//
// The single biggest cost is converting each running point back to affine
// coordinates for hashing, which needs one field inversion per key. We amortise
// that: a batch of `BATCH` points is accumulated in Jacobian coordinates (no
// inversion) and converted to affine with ONE inversion for the whole batch
// (Montgomery batch inversion), inside the vendored-libsecp256k1 shim in
// `csrc/shim.c`. See the `ec` module below.

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

// Number of consecutive keys produced per shim call and amortised under a single
// field inversion. Past ~64 the inversion is fully amortised; 512 keeps the
// scratch buffers comfortably in L2. Also the granularity of the shared counter.
const BATCH: usize = 512;

// After this many keys a worker draws a fresh random starting point instead of
// walking on forever, so coverage stays spread across the key space and the
// per-walk offset stays small. ~1.07e9 keys ≈ minutes of walking per stretch.
const WALK_SPAN: u64 = 1 << 30;

// Each worker sums keys locally and publishes to the shared counter in blocks of
// this size, so the atomic is touched rarely (no per-key cache-line contention).
const REPORT_BLOCK: u64 = 1 << 17; // 131_072

// ---------------------------------------------------------------------------
// Batched elliptic-curve walk (FFI to csrc/shim.c over vendored libsecp256k1).
//
// One `Walk` per worker thread — it owns C-side scratch buffers and a running
// Jacobian point, so it must not be shared between threads (it is `Send`, not
// `Sync`). Each `batch` call emits `n` consecutive compressed public keys (and,
// optionally, their uncompressed encodings) using one field inversion total.
// ---------------------------------------------------------------------------
mod ec {
    use std::ffi::c_void;

    extern "C" {
        fn ec_walk_new(cap: usize) -> *mut c_void;
        fn ec_walk_set_start(w: *mut c_void, pubkey: *const u8, len: usize) -> i32;
        fn ec_walk_batch(w: *mut c_void, n: usize, out_comp: *mut u8, out_uncomp: *mut u8);
        fn ec_walk_free(w: *mut c_void);
    }

    pub struct Walk {
        raw: *mut c_void,
        cap: usize,
    }

    // Safe to move to another thread: it owns its own C state exclusively.
    unsafe impl Send for Walk {}

    impl Walk {
        /// Create a walker able to emit up to `cap` keys per `batch` call.
        pub fn new(cap: usize) -> Self {
            let raw = unsafe { ec_walk_new(cap) };
            assert!(!raw.is_null(), "ec_walk_new: allocation failed");
            Walk { raw, cap }
        }

        /// Seed the running point from a serialized public key (33 or 65 bytes).
        /// Returns `false` if libsecp256k1 rejects the encoding.
        pub fn set_start(&mut self, pubkey: &[u8]) -> bool {
            unsafe { ec_walk_set_start(self.raw, pubkey.as_ptr(), pubkey.len()) == 1 }
        }

        /// Emit `n` consecutive public keys into `comp` (n*33 bytes) and, if
        /// `uncomp` is `Some`, their uncompressed encodings (n*65 bytes). Then the
        /// running point advances by `n` so the next call is contiguous.
        pub fn batch(&mut self, n: usize, comp: &mut [u8], uncomp: Option<&mut [u8]>) {
            assert!(n <= self.cap, "batch {n} exceeds capacity {}", self.cap);
            assert!(comp.len() >= n * 33, "compressed buffer too small");
            let up = match uncomp {
                Some(u) => {
                    assert!(u.len() >= n * 65, "uncompressed buffer too small");
                    u.as_mut_ptr()
                }
                None => std::ptr::null_mut(),
            };
            unsafe { ec_walk_batch(self.raw, n, comp.as_mut_ptr(), up) };
        }
    }

    impl Drop for Walk {
        fn drop(&mut self) {
            unsafe { ec_walk_free(self.raw) };
        }
    }
}

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

// hash160 for a whole batch of `n` consecutive 33-byte compressed pubkeys in
// `comp`, writing `n` 20-byte results into `out`. On aarch64 this dispatches to
// the SIMD path in csrc/hash_neon.c (ARMv8 SHA-256 + 4-way NEON RIPEMD-160,
// ~3.4x the crate); every other target uses the sha2/ripemd crates.
#[cfg(neon_hash)]
fn hash_batch(comp: &[u8], out: &mut [u8], n: usize) {
    extern "C" {
        fn hash160_many(pubkeys: *const u8, out20: *mut u8, n: usize);
    }
    debug_assert!(comp.len() >= n * 33 && out.len() >= n * 20);
    unsafe { hash160_many(comp.as_ptr(), out.as_mut_ptr(), n) };
}

#[cfg(not(neon_hash))]
fn hash_batch(comp: &[u8], out: &mut [u8], n: usize) {
    for i in 0..n {
        let h = hash160(&comp[i * 33..i * 33 + 33]);
        out[i * 20..i * 20 + 20].copy_from_slice(&h);
    }
}

fn main() {
    let db = Arc::new(load_database());
    let secp = Arc::new(Secp256k1::new());

    // Worker count: all logical cores by default, or PLUTUS_THREADS if set (useful
    // to keep the machine responsive, or to pin work to performance cores).
    let num_cores = std::env::var("PLUTUS_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(num_cpus::get);
    println!("Running on {} worker thread(s)", num_cores);

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
// Hot loop: batched sequential public keys, matched on hash160.
// ---------------------------------------------------------------------------
fn process(db: &Db, secp: &Secp256k1<All>, counter: &AtomicU64) {
    let mut rng = rand::thread_rng();
    let mut walk = ec::Walk::new(BATCH);

    // Reusable output buffers for the shim (never reallocated).
    let mut comp = vec![0u8; BATCH * 33];
    let mut h160 = vec![0u8; BATCH * 20];
    let mut uncomp = if CHECK_UNCOMPRESSED {
        vec![0u8; BATCH * 65]
    } else {
        Vec::new()
    };

    let mut since_report: u64 = 0;

    loop {
        // Fresh random starting point; seed the walker with its public key.
        let start_secret = random_secret(&mut rng);
        let start_pub = PublicKey::from_secret_key(secp, &start_secret);
        if !walk.set_start(&start_pub.serialize()) {
            continue; // unreachable for a valid secret key, but stay robust.
        }

        // Walk a long contiguous stretch from this start, in batches.
        let mut base: u64 = 0;
        while base < WALK_SPAN {
            if CHECK_UNCOMPRESSED {
                walk.batch(BATCH, &mut comp, Some(&mut uncomp));
            } else {
                walk.batch(BATCH, &mut comp, None);
            }

            // hash the whole batch of compressed pubkeys in one shot.
            hash_batch(&comp, &mut h160, BATCH);

            for (i, chunk) in h160.chunks_exact(20).enumerate() {
                let hash: &[u8; 20] = chunk.try_into().unwrap();
                if db.contains(hash) {
                    report_hit(secp, &start_secret, base + i as u64, true);
                }

                if CHECK_UNCOMPRESSED {
                    let hash_u = hash160(&uncomp[i * 65..i * 65 + 65]);
                    if db.contains(&hash_u) {
                        report_hit(secp, &start_secret, base + i as u64, false);
                    }
                }
            }

            base += BATCH as u64;
            since_report += BATCH as u64;
            if since_report >= REPORT_BLOCK {
                counter.fetch_add(since_report, Ordering::Relaxed);
                since_report = 0;
            }
        }
    }
}

/// The secp256k1 generator point G as a `PublicKey` (1 · G). Used by the tests as
/// the per-step addend so `combine` performs a plain point addition, mirroring the
/// shim's internal `+G` walk.
#[cfg(test)]
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

    // The batched shim must produce exactly the same compressed public keys as a
    // per-key `combine` walk — a fast-but-wrong batch would never match the DB.
    #[test]
    fn batch_walk_matches_combine() {
        let secp = Secp256k1::new();
        let g = generator(&secp);
        let start_pub = PublicKey::from_secret_key(&secp, &secret_from_u8(77));

        let n = 4096usize;
        let mut walk = ec::Walk::new(n);
        assert!(walk.set_start(&start_pub.serialize()));
        let mut comp = vec![0u8; n * 33];
        walk.batch(n, &mut comp, None);

        let mut pk = start_pub;
        for i in 0..n {
            assert_eq!(&comp[i * 33..i * 33 + 33], &pk.serialize()[..], "offset {i}");
            pk = pk.combine(&g).unwrap();
        }
    }

    // Consecutive batches must be contiguous: the running point has to advance by
    // exactly `n` between calls, or offsets would double-count / skip keys.
    #[test]
    fn batch_walk_continues_across_calls() {
        let secp = Secp256k1::new();
        let g = generator(&secp);
        let start_pub = PublicKey::from_secret_key(&secp, &secret_from_u8(5));

        let n = 300usize;
        let mut walk = ec::Walk::new(n);
        assert!(walk.set_start(&start_pub.serialize()));
        let mut first = vec![0u8; n * 33];
        let mut second = vec![0u8; n * 33];
        walk.batch(n, &mut first, None);
        walk.batch(n, &mut second, None);

        // Advance a reference walk to key #n, then compare the second batch.
        let mut pk = start_pub;
        for _ in 0..n {
            pk = pk.combine(&g).unwrap();
        }
        for i in 0..n {
            assert_eq!(&second[i * 33..i * 33 + 33], &pk.serialize()[..], "offset {}", n + i);
            pk = pk.combine(&g).unwrap();
        }
    }

    // The SIMD batch hasher must match the scalar crate hash160 for every key,
    // including a non-multiple-of-4 tail (remainder path in hash160_many).
    #[cfg(neon_hash)]
    #[test]
    fn neon_batch_hash160_matches_crate() {
        let secp = Secp256k1::new();
        let start_pub = PublicKey::from_secret_key(&secp, &secret_from_u8(7));

        let n = 130usize; // 130 % 4 == 2, exercises the tail
        let mut walk = ec::Walk::new(n);
        assert!(walk.set_start(&start_pub.serialize()));
        let mut comp = vec![0u8; n * 33];
        walk.batch(n, &mut comp, None);

        let mut neon = vec![0u8; n * 20];
        hash_batch(&comp, &mut neon, n);

        for i in 0..n {
            let want = hash160(&comp[i * 33..i * 33 + 33]);
            assert_eq!(&neon[i * 20..i * 20 + 20], &want[..], "key {i}");
        }
    }

    // With uncompressed output requested, both encodings must match `combine`, and
    // the compressed hash160 must equal what the DB-decode path stores.
    #[test]
    fn batch_uncompressed_matches_combine_and_db() {
        let secp = Secp256k1::new();
        let g = generator(&secp);
        // Start at key 1 so we can also check the compressed hash160 vs the DB bytes.
        let start_pub = PublicKey::from_secret_key(&secp, &secret_from_u8(1));

        let n = 16usize;
        let mut walk = ec::Walk::new(n);
        assert!(walk.set_start(&start_pub.serialize()));
        let mut comp = vec![0u8; n * 33];
        let mut unc = vec![0u8; n * 65];
        walk.batch(n, &mut comp, Some(&mut unc));

        let db_raw = bitcoin::base58::decode_check("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").unwrap();
        assert_eq!(&hash160(&comp[0..33])[..], &db_raw[1..21]);

        let mut pk = start_pub;
        for i in 0..n {
            assert_eq!(&comp[i * 33..i * 33 + 33], &pk.serialize()[..], "comp {i}");
            assert_eq!(&unc[i * 65..i * 65 + 65], &pk.serialize_uncompressed()[..], "unc {i}");
            pk = pk.combine(&g).unwrap();
        }
    }
}
