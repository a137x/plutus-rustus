extern crate bitcoin;
extern crate secp256k1;
extern crate num_cpus;

use std::fs::{self, OpenOptions};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use std::collections::HashSet;
use std::io::{Write, Read};
use std::fs::File;

use secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, PrivateKey, PublicKey};
use bitcoin::network::constants::Network;

use num_cpus::get;
use serde_pickle::from_slice;

const DB_VER: &str = "DATABASE-LOYCE";
const BATCH_SIZE: usize = 10000;
const OUTPUT_FILE: &str = "plutus.txt";
const PICKLE_EXTENSION: &str = ".pickle";

fn main() {
    let database = load_database_from_pickles();
    println!("Loaded {} addresses from pickle files.", database.len());

    let database_ = Arc::new(RwLock::new(database));
    let num_cores = get();
    println!("Running on {} logical cores", num_cores);

    process_concurrently(&database_, num_cores);
}

fn process_concurrently(database_: &Arc<RwLock<HashSet<String>>>, num_cores: usize) {
    let handles: Vec<_> = (0..num_cores)
        .map(|_| {
            let clone_database_ = Arc::clone(&database_);
            std::thread::spawn(move || {
                process_batch(&clone_database_);
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

fn write_to_file(data: &str, file_name: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .open(file_name)
        .expect("Unable to open file");
    file.write_all(data.as_bytes()).unwrap();
}

fn write_batch_to_file(batch: &[(PrivateKey, PublicKey, String)]) {
    let data = batch
        .iter()
        .map(|(private_key, public_key, address_string)| {
            format!("{}\n{}\n{}\n\n", private_key.to_wif(), public_key, address_string)
        })
        .collect::<String>();
    write_to_file(&data, OUTPUT_FILE);
}

fn process_batch(database_: &Arc<RwLock<HashSet<String>>>) {
    let mut count: f64 = 0.0;
    let start = Instant::now();
    let mut batch = Vec::with_capacity(BATCH_SIZE);

    loop {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let private_key = PrivateKey::new(secret_key, Network::Bitcoin);
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        let address = Address::p2pkh(&public_key, Network::Bitcoin);
        let address_string = address.to_string();

        if database_.read().unwrap().contains(&address_string) {
            batch.push((private_key, public_key, address_string));
        }

        count += 1.0;
        if batch.len() >= BATCH_SIZE || count % BATCH_SIZE as f64 == 0.0 {
            let current_core = std::thread::current().id();
            let elapsed = start.elapsed().as_secs_f64();
            println!(
                "Core {:?} checked {} addresses in {:.2?}, iter/sec: {}",
                current_core,
                count,
                elapsed,
                count / elapsed
            );

            if !batch.is_empty() {
                write_batch_to_file(&batch);
                batch.clear();
            }
        }
    }
}

fn load_pickle_data(path: &str) -> Vec<String> {
    let mut bytes = Vec::new();
    File::open(path).unwrap().read_to_end(&mut bytes).unwrap();
    let data: Vec<String> =
        from_slice(&bytes, Default::default()).expect("couldn't load pickle");
    data
}

fn load_database_from_pickles() -> HashSet<String> {
    let mut database = HashSet::new();
    let timer = Instant::now();
    let files = fs::read_dir(get_db_dir()).unwrap();

    for file in files {
        let file = file.unwrap();
        let file_name = file.file_name().into_string().unwrap();
        if file_name.ends_with(PICKLE_EXTENSION) {
            println!("Loading pickle data from file {:?}", file);
            let data = load_pickle_data(file.path().to_str().unwrap());
            database.extend(data);
            println!("Database size: {} addresses.", database.len());
        }
    }

    println!(
        "Load of pickle files completed in {:.2?}, database size: {}",
        timer.elapsed(),
        database.len()
    );

    database
}

fn get_db_dir() -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push("database");
    path.push(DB_VER);
    path.to_str().unwrap().to_string()
}