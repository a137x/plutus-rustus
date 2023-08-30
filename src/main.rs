extern crate bitcoin;
extern crate num_cpus;
extern crate secp256k1;

use std::fs::{self, OpenOptions};
use std::sync::{Arc, RwLock};
use std::{
    collections::HashSet,
    fs::File,
    io::{Read, Write},
    time::Instant,
};

use bitcoin::Address;
use bitcoin::{network::constants::Network, PrivateKey, PublicKey};
use secp256k1::{rand, Secp256k1, SecretKey};

use tokio::task;

const DB_VER: &str = "MAR_15_2021";

#[tokio::main]
async fn main() {
    // creating empty database
    let mut database = HashSet::new();
    let timer = Instant::now();
    let files = fs::read_dir(get_db_dir().as_str()).unwrap();
    for file in files {
        let file = file.unwrap();
        let file_name = file.file_name().into_string().unwrap();
        if file_name.ends_with(".pickle") {
            println!("Loading pickle slice from file {:?}", file);
            let data = load_pickle_slice(file.path().to_str().unwrap());
            // adding addresses to database
            for ad in data.iter() {
                database.insert(ad.to_string());
            }
            //database size
            println!("Database size {:?} addresses.", database.len());
        }
    }
    println!(
        "Load of pickle files completed in {:.2?}, database size: {:?}",
        timer.elapsed(),
        database.len()
    );

    // single thread version of processing
    // process(&database);

    // Multithread version of processing using tokio
    // atomic reference counting of database
    let database_ = Arc::new(RwLock::new(database));
    //get number of logical cores
    let num_cores = num_cpus::get();
    println!("Running on {} logical cores", num_cores);
    //run process on all available cores
    for _ in 0..num_cores {
        let clone_database_ = Arc::clone(&database_);
        task::spawn_blocking(move || {
            let current_core = std::thread::current().id();
            println!("Core {:?} started", current_core);
            let db = clone_database_.read().unwrap();
            process(&db);
        });
    }
}

// write data to file
fn write_to_file(data: &str, file_name: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .open(file_name)
        .expect("Unable to open file");
    file.write_all(data.as_bytes()).unwrap();
}

// function that checks address in database and if finds it, writes data to file
fn check_address(
    private_key: &PrivateKey,
    secret_key: SecretKey,
    address: &Address,
    database: &HashSet<String>,
    public_key: PublicKey,
) {
    let address_string = address.to_string();
    let _control_address = "15x5ugXCVkzTbs24mG2bu1RkpshW3FTYW8".to_string();
    if database.contains(&address_string) {
        let data = format!(
            "{}{}{}{}{}{}{}{}{}",
            secret_key.display_secret(),
            "\n",
            private_key.to_wif(),
            "\n",
            public_key.to_string(),
            "\n",
            address_string.as_str(),
            "\n",
            "\n",
        );
        write_to_file(data.as_str(), found_file_path().as_str());
    }
}

// load single pickle file from database directory
fn load_pickle_slice(path: &str) -> Vec<String> {
    let mut bytes = Vec::new();
    File::open(path).unwrap().read_to_end(&mut bytes).unwrap();
    let data: Vec<String> =
        serde_pickle::from_slice(&bytes, Default::default()).expect("couldn't load pickle");
    data
}

// get project dir
fn get_db_dir() -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push("database");
    path.push(DB_VER);
    path.to_str().unwrap().to_string()
}

// get found.txt file path
fn found_file_path() -> String {
    let mut path = std::env::current_dir().unwrap();
    path.push("plutus.txt");
    path.to_str().unwrap().to_string()
}

// infinite loop processing function
fn process(database: &HashSet<String>) {
    let mut count: f64 = 0.0;
    let start = Instant::now();
    loop {
        // Generating secret key
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let private_key = PrivateKey::new(secret_key, Network::Bitcoin);
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        // Generate pay-to-pubkey-hash (P2PKH) wallet address
        let address = Address::p2pkh(&public_key, Network::Bitcoin);

        // check address against database
        check_address(&private_key, secret_key, &address, database, public_key);

        // FOR BENCHMARKING ONLY! (has to be commented out for performance gain)
        count += 1.0;
        if count % 100000.0 == 0.0 {
            let current_core = std::thread::current().id();
            let elapsed = start.elapsed().as_secs_f64();
            println!(
                "Core {:?} checked {} addresses in {:.2?}, iter/sec: {}",
                current_core,
                count,
                elapsed,
                count / elapsed
            );
        }
    }
}
