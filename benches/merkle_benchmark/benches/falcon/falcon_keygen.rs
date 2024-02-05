use criterion::{
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion
};
use merkle_benchmark::MESSAGE_COUNT_RANGE;
use oqs::*;

fn falcon_keygen_benchmark(c:&mut Criterion) {

    let mut keygen_group = c.benchmark_group("merkle Falcon keygen");
    for i in MESSAGE_COUNT_RANGE.iter() {
        let sigalg = sig::Sig::new(sig::Algorithm::Falcon512).unwrap();
        keygen_group.bench_with_input(
            BenchmarkId::from_parameter(*i),
            &i, 
            |b, &_i| { b.iter(|| {
                //follows what we are benchmarking in this group
                let (_pk, _sk) = sigalg.keypair().unwrap();
            });
        });       
    } keygen_group.finish();
}

criterion_group!(benches, falcon_keygen_benchmark);
criterion_main!(benches);
