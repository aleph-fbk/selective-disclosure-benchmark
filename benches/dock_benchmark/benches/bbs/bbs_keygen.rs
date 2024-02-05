use ark_bls12_381::Bls12_381;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use bbs_plus::prelude::{
    KeypairG2,
    SignatureParams23G1,
};
use blake2::Blake2b512;
use dock_benchmark::MCRU32;
use rand::Rng;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

// benchmark for sk and pk generation using an rng
fn bbs_keygen_rng_benchmark(c:&mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let mut keygen_group = c.benchmark_group("dock BBS keygen");
    for i in MCRU32.iter() {
        keygen_group.bench_with_input(
            BenchmarkId::from_parameter(*i),
            &i, 
            |b, &_i| { b.iter(|| {
                //follows what we are benchmarking in this group
                let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(black_box(&mut rng), *i);
                let _keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(black_box(&mut rng), &params);
            });
        });       
    } keygen_group.finish();
}

// benchmark for sk and pk generation using as seed 32 random bytes
fn bbs_keygen_seed_benchmark(c:&mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut keygen_group = c.benchmark_group("dock BBS keygen seed");
    for i in MCRU32.iter() {
        let seed: [u8; 32] = rng.gen();
        keygen_group.bench_with_input(
            BenchmarkId::from_parameter(*i),
            &i, 
            |b, &_i| { b.iter(|| {
                //follows what we are benchmarking in this group
                let params = SignatureParams23G1::<Bls12_381>::new::<Blake2b512>(&[1, 2, 3, 4], black_box(*i));
                let _keypair = KeypairG2::<Bls12_381>::generate_using_seed_and_bbs23_params::<Blake2b512>(black_box(&seed), &params);
            });
        });       
    } keygen_group.finish();
}

criterion_group!(
    benches,
    bbs_keygen_rng_benchmark,
    bbs_keygen_seed_benchmark
);
criterion_main!(benches);
