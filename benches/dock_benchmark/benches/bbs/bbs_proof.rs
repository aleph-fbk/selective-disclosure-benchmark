use std::collections::BTreeMap;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use bbs_plus::prelude::{
    KeypairG2, MessageOrBlinding, PoKOfSignature23G1Protocol, Signature23G1, SignatureParams23G1,
};

use bbs_plus::proof_23::PoKOfSignature23G1Protocol as TZprotocol;

use dock_benchmark::setup_bbs_plus;
use dock_benchmark::{MCR, MCRU32};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

type Fr = <Bls12_381 as Pairing>::ScalarField;

fn pok_sig_benchmark(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    setup_bbs_plus!(
        SignatureParams23G1,
        KeypairG2,
        rng,
        MCRU32,
        messages_range,
        params_range,
        keypair_range,
        generate_using_rng_and_bbs23_params
    );

    let sigs_range = (0..MCR.len())
        .map(|i| {
            Signature23G1::<Bls12_381>::new(
                &mut rng,
                &messages_range[i],
                &keypair_range[i].secret_key,
                &params_range[i],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();


        for i in 0..MCR.len() {

            let mut prove_group = c.benchmark_group(format!("dock BBS presentation generation with {} attributes", MCR[i]));
            for ri in 1..MCR[i] + 1 {

                prove_group.bench_with_input(
                    BenchmarkId::from_parameter(format!("Revealing {} attributes", ri)),
                    &ri,
                    |b, &_i| {
                        b.iter(|| {
                            let pok = PoKOfSignature23G1Protocol::init(
                                &mut rng,
                                black_box(&sigs_range[i]),
                                black_box(&params_range[i]),
                                black_box(messages_range[i].iter().enumerate().map(|(idx, msg)| {
                                    if idx >= ri {
                                        MessageOrBlinding::BlindMessageRandomly(msg)
                                    } else {
                                        MessageOrBlinding::RevealMessage(msg)
                                    }
                                })),
                            )
                            .unwrap();
                            let challenge = Fr::rand(&mut rng);
                            pok.gen_proof(&challenge).unwrap();
                        });
                },
            );
        }
        prove_group.finish();
    }

    for i in 0..MCR.len() {

        let mut verify_group = c.benchmark_group(format!("dock BBS presentation verification with {} attributes", MCR[i]));
        for ri in 1..MCR[i] + 1 {
            let pok = PoKOfSignature23G1Protocol::init(
                &mut rng,
                &sigs_range[i],
                &params_range[i],
                messages_range[i].iter().enumerate().map(|(idx, msg)| {
                    if idx >= ri {
                        MessageOrBlinding::BlindMessageRandomly(msg)
                    } else {
                        MessageOrBlinding::RevealMessage(msg)
                    }
                }),
            )
            .unwrap();

            // Not benchmarking challenge contribution as that is just serialization
            let challenge = Fr::rand(&mut rng);
            let proof = pok.gen_proof(&challenge).unwrap();

            let mut rev_mex = BTreeMap::new();
            for mex in 0..ri {
                rev_mex.insert(mex, messages_range[i][mex]);
            }
            verify_group.bench_with_input(
                BenchmarkId::from_parameter(format!(
                    "Revealing {} attributes",
                    ri
                )),
                &ri,
                |b, &_i| {
                    b.iter(|| {
                        proof
                            .verify(
                                black_box(&rev_mex),
                                black_box(&challenge),
                                black_box(keypair_range[i].public_key.clone()),
                                black_box(params_range[i].clone()),
                            )
                            .unwrap();
                    });
                },
            );
        } verify_group.finish();
    } 
}

fn pok_sig_tz_benchmark(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0u64);
    setup_bbs_plus!(
        SignatureParams23G1,
        KeypairG2,
        rng,
        MCRU32,
        messages_range,
        params_range,
        keypair_range,
        generate_using_rng_and_bbs23_params
    );

    let sigs_range = (0..MCR.len())
        .map(|i| {
            Signature23G1::<Bls12_381>::new(
                &mut rng,
                &messages_range[i],
                &keypair_range[i].secret_key,
                &params_range[i],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();


        for i in 0..MCR.len() {

            let mut prove_group = c.benchmark_group(format!("dock TZ BBS presentation generation with {} attributes", MCR[i]));
            for ri in 1..MCR[i] + 1 {

                prove_group.bench_with_input(
                    BenchmarkId::from_parameter(format!("Revealing {} attributes", ri)),
                    &ri,
                    |b, &_i| {
                        b.iter(|| {
                            let pok = TZprotocol::init(
                                &mut rng,
                                None,
                                None,
                                black_box(&sigs_range[i]),
                                black_box(&params_range[i]),
                                black_box(messages_range[i].iter().enumerate().map(|(idx, msg)| {
                                    if idx >= ri {
                                        MessageOrBlinding::BlindMessageRandomly(msg)
                                    } else {
                                        MessageOrBlinding::RevealMessage(msg)
                                    }
                                })),
                            )
                            .unwrap();
                            let challenge = Fr::rand(&mut rng);
                            pok.gen_proof(&challenge).unwrap();
                        });
                },
            );
        }
        prove_group.finish();
    }

    for i in 0..MCR.len() {

        let mut verify_group = c.benchmark_group(format!("dock TZ BBS presentation verification with {} attributes", MCR[i]));
        for ri in 1..MCR[i] + 1 {
            let pok = TZprotocol::init(
                &mut rng,
                None,
                None,
                &sigs_range[i],
                &params_range[i],
                messages_range[i].iter().enumerate().map(|(idx, msg)| {
                    if idx >= ri {
                        MessageOrBlinding::BlindMessageRandomly(msg)
                    } else {
                        MessageOrBlinding::RevealMessage(msg)
                    }
                }),
            )
            .unwrap();

            // Not benchmarking challenge contribution as that is just serialization
            let challenge = Fr::rand(&mut rng);
            let proof = pok.gen_proof(&challenge).unwrap();

            let mut rev_mex = BTreeMap::new();
            for mex in 0..ri {
                rev_mex.insert(mex, messages_range[i][mex]);
            }
            verify_group.bench_with_input(
                BenchmarkId::from_parameter(format!(
                    "Revealing {} attributes",
                    ri
                )),
                &ri,
                |b, &_i| {
                    b.iter(|| {
                        proof
                            .verify(
                                black_box(&rev_mex),
                                black_box(&challenge),
                                black_box(keypair_range[i].public_key.clone()),
                                black_box(params_range[i].clone()),
                            )
                            .unwrap();
                    });
                },
            );
        } verify_group.finish();
    } 
}

criterion_group!(
    benches, 
    pok_sig_benchmark,
    pok_sig_tz_benchmark,
);
criterion_main!(benches);
