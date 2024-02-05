# merkle-benchmark

This folder contains benchmarks for Merkle trees solution for selective disclosure using the library [rs-merkle](https://docs.rs/rs_merkle/latest/rs_merkle/) with different signatures, namely  
[ed25519_dalek](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/) and the post quantum signatures implemented in [oqs](https://docs.rs/oqs/0.8.0/oqs/), Falcon, Sphincs and Dilithium. 

## Merkle trees
 1. generate a keypair;
 2. generate a signature; 
 3. verify that signature;
 4. creating a merkle proof for an increasing number of attributes and disclosed messages;
 5. verify that proof.

To run point 1 run `cargo bench --bench=<signature>_keypair`   
To run points 2-3, run `cargo bench --bench=<signature>_signature`  
To run the last two points, run `cargo bench --bench=<signature>_proof`

To run all benchmarks for <signature> run `cargo bench --bench=<signature>*`
