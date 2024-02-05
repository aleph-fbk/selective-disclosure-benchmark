use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion
};
use merkle_benchmark::MESSAGE_COUNT_RANGE;
use ed25519_dalek::Keypair;

fn merkle_keygen_benchmark(c:&mut Criterion) {

    let mut keygen_group = c.benchmark_group("merkle EdDSA keygen");
    for i in MESSAGE_COUNT_RANGE.iter() {
        let mut rng = rand::thread_rng();
        keygen_group.bench_with_input(
            BenchmarkId::from_parameter(*i),
            &i, 
            |b, &_i| { b.iter(|| {
                //follows what we are benchmarking in this group

                //notice a couple of things:
                //we are benchmarking ed25519_dalek, 
                //it always has the same input, it does not grow with the number of messages

                //?we can also bench the rng since bbs and cl also do that in the keygen functions?
                
                Keypair::generate(black_box(&mut rng));
            });
        });       
    } keygen_group.finish();
}

criterion_group!(benches, merkle_keygen_benchmark);
criterion_main!(benches);
