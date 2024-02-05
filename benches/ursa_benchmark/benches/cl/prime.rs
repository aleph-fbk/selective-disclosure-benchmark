use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    Criterion,
};
use ursa::cl::{
    helpers::generate_safe_prime, 
    constants::LARGE_PRIME, 
};


fn prime_benchmark(c:&mut Criterion) {
    c.bench_function("safe prime", |b| b.iter(||
        generate_safe_prime(black_box(LARGE_PRIME)).unwrap())
    );
}

criterion_group!(benches, prime_benchmark);
criterion_main!(benches);