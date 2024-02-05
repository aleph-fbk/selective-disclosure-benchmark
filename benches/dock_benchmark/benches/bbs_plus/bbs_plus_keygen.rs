use ark_bls12_381::Bls12_381;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use bbs_plus::prelude::{
    KeypairG2,
    SignatureParamsG1,
};
use dock_benchmark::MCRU32;
use blake2::Blake2b512;
use rand::Rng;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn bbs_keygen_rng_benchmark(c:&mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    let mut keygen_group = c.benchmark_group("dock BBS+ keygen");
    for i in MCRU32.iter() {  
        keygen_group.bench_with_input(
            BenchmarkId::from_parameter(*i),
            &i, 
            |b, &_i| { b.iter(|| {
                //follows what we are benchmarking in this group
                let params = SignatureParamsG1::<Bls12_381>::generate_using_rng(black_box(&mut rng), *i);
                let _keypair = KeypairG2::<Bls12_381>::generate_using_rng(black_box(&mut rng), &params);
            });
        });       
    } keygen_group.finish();
}

fn bbs_keygen_seed_benchmark(c:&mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut keygen_group = c.benchmark_group("dock BBS+ keygen seed");
    for i in MCRU32.iter() {
        let seed: [u8; 32] = rng.gen();
        keygen_group.bench_with_input(
            BenchmarkId::from_parameter(*i),
            &i, 
            |b, &_i| { b.iter(|| {
                //follows what we are benchmarking in this group
                let params = SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(&seed, black_box(*i));
                let _keypair = KeypairG2::<Bls12_381>::generate_using_seed::<Blake2b512>(black_box(&seed), &params);
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
