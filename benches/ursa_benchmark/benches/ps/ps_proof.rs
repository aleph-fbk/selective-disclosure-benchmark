use ursa_benchmark::MESSAGE_COUNT_RANGE;

use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion
};

use zmix::amcl_wrapper::field_elem::FieldElement;
use std::collections::{HashMap, HashSet};

use zmix::signatures::ps::keys::{keygen as ps_keys_generate, Params};
use zmix::signatures::ps::pok_sig::PoKOfSignature as PSPoKOfSignature;
use zmix::signatures::ps::signature::Signature as PSSignature;
use zmix::signatures::SignatureMessageVector;

fn presentation_benchmark(c: &mut Criterion) {

    for i in 0..MESSAGE_COUNT_RANGE.len() {
        //build a sign
        let attrs_field = (0..MESSAGE_COUNT_RANGE[i])
                .map(|_h| FieldElement::random())
                .collect::<Vec<_>>();
            let attributes: SignatureMessageVector = attrs_field.clone().into();
            let label = format!("ps sign {} MESSAGE_COUNT_RANGE[i]", MESSAGE_COUNT_RANGE[i]);
            let params = Params::new(label.as_bytes());
            let (vk, sk) = ps_keys_generate(MESSAGE_COUNT_RANGE[i], &params);
            let sig = PSSignature::new(attributes.as_slice(), &sk, &params).unwrap();

        let mut prove_group = c.benchmark_group(format!("ursa PS presentation generation with {} attributes", MESSAGE_COUNT_RANGE[i]));
        for ri in 1..MESSAGE_COUNT_RANGE[i] + 1 {

            //bench only the PoK generation
            prove_group.bench_with_input(
                BenchmarkId::from_parameter(format!("Revealing {} attributes", ri)),
                &ri,
                |b, &_i| {
                    b.iter(|| {
                        let pok = PSPoKOfSignature::init(
                            black_box(&sig),
                            black_box(&vk),
                            black_box(&params),
                            black_box(attributes.as_slice()),
                            None,
                            (0..ri).map(|h| h).collect::<HashSet<_>>(),
                        )
                        .unwrap();
                        let chal = FieldElement::from_msg_hash(&pok.to_bytes());
                        pok.gen_proof(&chal).unwrap()
                    }
                )
            });
        } prove_group.finish();
    }
}

fn verification_benchmark(c: &mut Criterion) {

    for i in 0..MESSAGE_COUNT_RANGE.len() {
        //build a sign again
        let attrs_field = (0..MESSAGE_COUNT_RANGE[i])
                .map(|_h| FieldElement::random())
                .collect::<Vec<_>>();
            let attributes: SignatureMessageVector = attrs_field.clone().into();
            let label = format!("ps sign {} MESSAGE_COUNT_RANGE[i]", MESSAGE_COUNT_RANGE[i]);
            let params = Params::new(label.as_bytes());
            let (vk, sk) = ps_keys_generate(MESSAGE_COUNT_RANGE[i], &params);
            let sig = PSSignature::new(attributes.as_slice(), &sk, &params).unwrap();

        let mut verify_group = c.benchmark_group(format!("ursa PS presentation verification with {} attributes", MESSAGE_COUNT_RANGE[i]));
        for ri in 1..MESSAGE_COUNT_RANGE[i] + 1 {
            //build a pok
            let proof_messages = (0..ri)
                .map(|h| {
                    h
                }).collect::<HashSet<_>>();
            let vec_messages = (0..ri)
                .map(|h| {
                    let att: Vec<FieldElement> = attributes.clone().into();
                    (h, att[h].clone())
                }).collect::<Vec<_>>();

            let hm_message = HashMap::from_iter(vec_messages);

            let pok = PSPoKOfSignature::init(
                &sig,
                &vk,
                &params,
                attributes.as_slice(),
                None,
                proof_messages,
            )
            .unwrap();
            let chal = FieldElement::from_msg_hash(&pok.to_bytes());
            let proof = pok.gen_proof(&chal).unwrap();

            //bench only the verification step
            verify_group.bench_with_input(
                BenchmarkId::from_parameter(format!(
                    "Revealing {} attributes",
                    ri
                )),
                &ri,
                |b, &_i| {
                    b.iter(|| {
                        proof.verify(
                            black_box(&vk), 
                            black_box(&params), 
                            black_box(hm_message.clone()), 
                            black_box(&chal), 
                        ).unwrap()
                    })
                });
        } verify_group.finish();
    }
}

criterion_group!(benches, presentation_benchmark, verification_benchmark);
criterion_main!(benches);
