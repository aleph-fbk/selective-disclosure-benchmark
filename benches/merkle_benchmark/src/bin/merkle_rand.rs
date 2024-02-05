use rs_merkle::{MerkleTree, algorithms::Sha256, Hasher,};
//use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::fs;

fn main() {

if !Path::new("data").is_dir() {
    fs::create_dir("data").unwrap();
}
if !Path::new("data/merkle_rand").is_dir() {
    fs::create_dir("data/merkle_rand").unwrap();
}

let leaf_values: Vec<String> = (0..33)
    .map(|i| format!("{}", i) )
    .collect();

let leaves: Vec<[u8; 32]> = leaf_values
    .iter()
    .map(|x| Sha256::hash(x.as_bytes()))
    .collect();

let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);

for i in 0..leaf_values.len() {
    //a .csv file in data for each nD
    let mut file = File::create(format!("data/merkle_rand/{}.csv", i + 1)).unwrap();
    let mut rng = &mut rand::thread_rng();
    writeln!(file, "{}", i + 1).unwrap();

    //let mut hs = HashSet::new();
    //sampling 5000 random possible combinations of leaves
    for _ in 0..50000 {
        //randomly pick a vector with i + 1 values without repetition inside
        let indices_to_prove = rand::seq::index::sample(&mut rng, 33, i + 1).into_vec();
        /* 
        indices_to_prove.sort();
        if !hs.insert(indices_to_prove.clone()) {
            continue
        }
        */
        let merkle_proof = merkle_tree.proof(&indices_to_prove);
        let proof_len = merkle_proof.to_bytes().len();
        let s = format!("{}", proof_len);

        writeln!(file, "{}", s).unwrap();
    }
}
}
