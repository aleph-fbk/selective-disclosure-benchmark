# ursa-benchmark

This folder contains benchmarks PS and CL signatures implemented in the [Hyperledger Ursa](https://github.com/hyperledger-archives/ursa) project.

## Install

To run these benchmarks, a local copy of `libursa` and `libzmix` is necessary. The following shell commands will clone a local copy from the github repo to a folder named `ursa`, then replace the  `ursa/libursa/src/cl` folder with the one provided in the `cl` folder from this repository.

Note, the version of Ursa for which our modifications were made is [commit 5cd3331](https://github.com/hyperledger-archives/ursa/tree/5cd3331e1428daad73a0e0d857f8bd01affb4441) from August 4th, 2022. Since Hyperledger Ursa was moved to end-of-life on April 27th, 2023, we have not invested the time to update them.

```sh
mkdir ursa
cd ursa
git init
git branch -m main
git remote add -f origin git@github.com:hyperledger-archives/ursa.git 
git config core.sparseCheckout true
echo "libursa/" >> .git/info/sparse-checkout
echo "libzmix/" >> .git/info/sparse-checkout
git merge 5cd3331
cd ..
cp cl/* ursa/libursa/src/cl/
```

## Usage

### CL signature
 1. generate a keypair;
 2. generate a signature; 
 3. verify that signature;
 4. creating a proof of knowledge for an increasing number of attributes and disclosed messages;
 5. verify that proof.

To run point 1 run `cargo bench --bench=cl_keypair`   
To run points 2-3, run `cargo bench --bench=cl_signature`  
To run points 4-5, run `cargo bench --bench=cl_proof`

To run all benchmarks for CL run `cargo bench --bench=cl*`   

### PS signature
 6. generate a keypair;
 7. generate a signature; 
 8. verify that signature;
 9. creating a proof of knowledge for an increasing number of attributes and disclosed messages;
 10. verify that proof.

To run point 6 run `cargo bench --bench=ps_keypair`   
To run points 7-8, run `cargo bench --bench=ps_signature`  
To run points 9-10, run `cargo bench --bench=ps_proof`

To run all benchmarks for PS run `cargo bench --bench=ps*`   

