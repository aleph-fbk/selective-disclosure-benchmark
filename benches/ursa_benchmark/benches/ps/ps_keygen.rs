use zmix::signatures::ps::keys::{keygen as ps_keys_generate, Params};

use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion
};

use ursa_benchmark::MESSAGE_COUNT_RANGE;

fn ps_paramgen_benchmark(c:&mut Criterion) {

    let mut keygen_group = c.benchmark_group("ursa PS paramgen");
    for i in MESSAGE_COUNT_RANGE.iter() {
        keygen_group.bench_with_input(
            BenchmarkId::from_parameter(*i),
            &i, 
            |b, &i| { b.iter(|| {
                let _params = Params::new(format!("create ps key for {}", *i).as_bytes());
            });
        });       
    } keygen_group.finish();
}

fn ps_keygen_benchmark(c:&mut Criterion) {

    let mut keygen_group = c.benchmark_group("ursa PS keygen");
    for i in MESSAGE_COUNT_RANGE.iter() {
        let params = Params::new(format!("create ps key for {}", *i).as_bytes());
        keygen_group.bench_with_input(
            BenchmarkId::from_parameter(*i),
            &i, 
            |b, &i| { b.iter(|| {
                ps_keys_generate(black_box(*i), &params)
            });
        });       
    } keygen_group.finish();
}

criterion_group!(
    benches,
    ps_paramgen_benchmark,
    ps_keygen_benchmark
);
criterion_main!(benches);
