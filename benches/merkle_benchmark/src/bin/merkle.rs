use rs_merkle::{
    MerkleTree, 
    algorithms::Sha256, 
    Hasher, 
};
use merkle_benchmark::{
    setup_merkle,
};
use ed25519_dalek::{
    Keypair,
    Signer,
};

fn main() {
    let message_count_range = [33];
    setup_merkle!(
        message_count_range,
        leaves_range,
        merkle_trees_range,
        keypair_range
    );

    let mut sign_root_range = vec![];
    for i in 0..message_count_range.len() {
        //we sign the merkle root
        let merkle_root = merkle_trees_range[i].root().unwrap();
        sign_root_range.push(keypair_range[i].sign(&merkle_root));
    }
    
    let mut leaf_indices_range = vec![];
    for (_i, count) in message_count_range.iter().enumerate() {
        let leaf_indices = (0..*count).collect::<Vec<_>>();
        leaf_indices_range.push(leaf_indices);
    }
    let mut merkle_root_range = vec![];
    let mut proof_range = vec![];
    let mut leaves_to_prove_range = vec![];
    let mut indices_to_prove_range = vec![];

    for (i, _count) in message_count_range.iter().enumerate() {
        let mut proofs = vec![];
        let mut leaves_to_proves = vec![];
        let mut indices_to_proves = vec![];

        let merkle_root = merkle_trees_range[i].root().unwrap();
        for indices in leaf_indices_range[i].iter() {
            let indices_to_prove = (0..=*indices).collect::<Vec<_>>();
            let leaves_to_prove = leaves_range[i].get(0..=*indices).unwrap();
            let merkle_proof = merkle_trees_range[i].proof(&indices_to_prove);
            let proof_bytes = merkle_proof.to_bytes();
            //let proof = MerkleProof::<Sha256>::try_from(proof_bytes).unwrap();

            proofs.push(proof_bytes);
            leaves_to_proves.push(leaves_to_prove);
            indices_to_proves.push(indices_to_prove);
        }
        merkle_root_range.push(merkle_root);
        proof_range.push(proofs);
        leaves_to_prove_range.push(leaves_to_proves);
        indices_to_prove_range.push(indices_to_proves);
    }

    println!("nD, bytes");
    for i in 0..message_count_range.len() {
        for j in 0..proof_range[i].len() {
            println!("{}, {}", j + 1, proof_range[i][j].len());
        }}
}