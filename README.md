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

To generate plots:

```bash
python3 matplotlib/plot_Presentation.py
```

## Installation

Hyperledger [Ursa](https://github.com/hyperledger/ursa) has external dependencies.
Note that we have a slightly modified version of libursa, which is included in `/ursa`. We had to make some methods public, adjust some parameters to reach a higher level of security for comparison with other mechanisms, and add some functionalities in order to properly test a CL implementation without a blinded signature.

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

