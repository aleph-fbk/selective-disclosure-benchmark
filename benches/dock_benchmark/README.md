# dock-benchmark

This folder contains benchmarks for BBS+ and BBS signatures implemented in [docknetwork](https://github.com/docknetwork/crypto/tree/main).

### BBS signature 
 1. generate a keypair;
 2. generate a signature; 
 3. verify that signature;
 4. creating a proof of knowledge for an increasing number of attributes and disclosed messages;
 5. verify that proof.

To run point 1 run `cargo bench --bench=bbs_keypair`   
To run points 2-3, run `cargo bench --bench=bbs_signature`  
To run points 4-5, run `cargo bench --bench=bbs_proof`

## BBS+ signature
 6. generate a keypair;
 7. generate a signature; 
 8. verify that signature;
 9. creating a proof of knowledge for an increasing number of attributes and disclosed messages;
 10. verify that proof.

To run point 6 run `cargo bench --bench=bbs_plus_keypair`   
To run points 7-8, run `cargo bench --bench=bbs_plus_signature`  
To run points 9-10, run `cargo bench --bench=bbs_plus_proof`
