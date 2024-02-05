use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion
};
use ursa_benchmark::MESSAGE_COUNT_RANGE;

use zmix::amcl_wrapper::field_elem::FieldElement;
use zmix::signatures::ps::keys::{keygen as ps_keys_generate, Params};
use zmix::signatures::ps::signature::Signature as PSSignature;
use zmix::signatures::SignatureMessageVector;

fn ps_sign_benchmark(c:&mut Criterion) {
    let mut sign_group = c.benchmark_group("ursa PS signing");
    for (i, count) in MESSAGE_COUNT_RANGE.iter().enumerate() {
        let attributes = SignatureMessageVector::random(MESSAGE_COUNT_RANGE[i]);
        let label = format!("ps sign {} MESSAGE_COUNT_RANGE[i]", MESSAGE_COUNT_RANGE[i]);
        let params = Params::new(label.as_bytes());
        let (_, sk) = ps_keys_generate(MESSAGE_COUNT_RANGE[i], &params);

        //only benchmark the signature generation
        sign_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &_i| {
            b.iter(||
                PSSignature::new(
                    black_box(attributes.as_slice()), 
                    black_box(&sk), 
                    black_box(&params)
                )
            );
        });
    }
    sign_group.finish();

    let mut verify_group = c.benchmark_group("ursa PS verifying");
    for (i, count) in MESSAGE_COUNT_RANGE.iter().enumerate() {

        //build a sign
        let attrs_field = (0..MESSAGE_COUNT_RANGE[i])
                .map(|_h| FieldElement::random())
                .collect::<Vec<_>>();
        let attributes: SignatureMessageVector = attrs_field.clone().into();
        let label = format!("ps sign {} MESSAGE_COUNT_RANGE[i]", MESSAGE_COUNT_RANGE[i]);
        let params = Params::new(label.as_bytes());
        let (vk, sk) = ps_keys_generate(MESSAGE_COUNT_RANGE[i], &params);
        let sig = PSSignature::new(attributes.as_slice(), &sk, &params).unwrap();

        //only benchmark the verification
        verify_group.bench_with_input(BenchmarkId::from_parameter(*count), &i, |b, &_i| {
            b.iter(|| 
                sig
                    .verify(
                    black_box(attributes.as_slice()),
                    black_box(&vk),
                    black_box(&params)
                    )
                    .unwrap()
                )
        });
    }
    verify_group.finish();
}

criterion_group!(benches, ps_sign_benchmark);
criterion_main!(benches);
