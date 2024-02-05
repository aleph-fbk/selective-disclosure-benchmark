# selective-disclosure-benchmark
Benchmarks of cryptographic mechanisms for selective disclosure of attributes. Please refer to [arxiv.org/abs/2401.08196](https://doi.org/10.48550/arXiv.2401.08196) for a full description.

## Usage

To run all benchmarks:
```bash
cargo bench
```

For cryptographic mechanisms `cm` in `bbs, cl, merkle, ps`, benchmarks are available for the following operations:
 1. generate a keypair;    
 2. generate a signature;  
 3. verify that signature;
 4. create a proof of knowledge for an increasing number of attributes and disclosed messages;
 5. verify that proof.

To bench 1: `cargo bench --bench=cm_keypair`   
To bench 2-3: `cargo bench --bench=cm_signature`  
To bench 4-5: `cargo bench --bench=cm_proof`

Before generating summary plots, two additional steps should be performed.

The most expensive operation by far in `CL` is primality testing for large primes. The script in `prime_repeat.py` repeats safe prime generation for 8 runs:

```
cd benches/ursa_benchmark
python3 src/prime_repeat.py
cd ../..
```

Secondly, the Merkle tree proof size depends on which attributes are disclosed. To estimate a realistic scenario, we sample the possible combinations of disclosed attributes at random. The following scripts sample possible combinations, saving the measured proof sizes in separate `.csv` files:

```
cd benches/merkle_benchmark
cargo run --bin merkle >> merkle_proofbytes.csv
cargo run --bin merkle_rand
mv merkle_proofbytes.csv ../../data
cd ../..
python3 src/merkle_rand_summary.py
cd ../..
```

To generate plots, from the repo's root folder:

```bash
python3 matplotlib/issuing_scatter.py
python3 matplotlib/keygen_scatter.py
python3 matplotlib/presentation_scatter.py
python3 matplotlib/key_vs_holder_proof.py
```

Plots in `.pdf` and `.svg` format will be saved in `plots/`.

## Installation

Hyperledger [Ursa](https://github.com/hyperledger/ursa) has external dependencies.
Note that we have a slightly modified version of libursa, which is included in `ursa/`. We had to make some methods public, adjust some parameters to reach a higher level of security for comparison with other mechanisms, and add some functionalities in order to properly test a CL implementation without a blinded signature.

Install rust following e.g., [doc.rust-lang.org](https://doc.rust-lang.org/book/ch01-01-installation.html):

```bash
sudo apt install curl pkg-config
curl --proto '=https' --tlsv1.3 https://sh.rustup.rs -sSf | sh
```

Install openssl with development packages (required by Ursa):

```bash
sudo apt install libssl-dev
```

Install [liboqs](https://github.com/open-quantum-safe/liboqs) dependencies for quantum-safe signatures:

```bash
sudo apt install astyle cmake clang gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind
```

### matplotlib

Additional dependencies to generate graphs in matplotlib:

```bash
sudo apt install --upgrade python3-pip
sudo apt install texlive-latex-extra dvipng
python3 -m pip install -r ./matplotlib/requirements.txt
```

