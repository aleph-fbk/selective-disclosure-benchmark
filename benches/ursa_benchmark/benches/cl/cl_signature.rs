use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion
};
use ursa::bn::BigNumber;
use ursa::cl::constants::{
    LARGE_E_START_VALUE, 
    LARGE_E_END_RANGE_VALUE, LARGE_VPRIME, LARGE_VPRIME_VALUE, 
    //LARGE_VPRIME,
};
use ursa::cl::helpers::{
    //generate_v_prime_prime, 
    generate_prime_in_range, bn_rand, bitwise_or_big_int, 
    //bn_rand
};
use ursa::cl::{
    prover::Prover, 
    issuer::Issuer, 
    CredentialSchema, 
    CredentialPublicKey, 
    CredentialPrivateKey, 
    BlindedCredentialSecrets,
    new_nonce,
};
use std::collections::BTreeSet;
use ursa_benchmark::{
    setup_cl,
    MESSAGE_COUNT_RANGE,
    HARDCODED_HASH,
};

fn cl_sign_benchmark(c:&mut Criterion) {

    //setup the messages and the keypairs, and a lot of necessary stuff
    setup_cl!(
        message_range, 
        MESSAGE_COUNT_RANGE, 
        keypair_range, 
        credential_pair_range,
        credential_values_range,
        credential_schema_range,
        blinded_cred_secrets_range,
        v_prime_range
    );

    //required stuff
    let credential_context = Issuer::_gen_credential_context("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW", None).unwrap();
    let mut sign_group = c.benchmark_group("ursa CL signing");
        for (i, count) in MESSAGE_COUNT_RANGE.iter().enumerate() {
            sign_group.bench_with_input(
                BenchmarkId::from_parameter(*count),
                &i, 
                |b, &i| { b.iter(|| {
                    //follows what we are benchmarking in this group
                    //primary stuff should be the core CL without the blindings
                    //it seems to almost not have any difference in performance at n*attributes variation?
                    Issuer::_sign_primary_credential(
                        black_box(&credential_pair_range[i].0),
                        black_box(&credential_pair_range[i].1),
                        black_box(&credential_context),
                        black_box(&credential_values_range[i]),
                        //black_box(&generate_v_prime_prime().unwrap()),
                        {
                            let a = bn_rand(black_box(LARGE_VPRIME)).unwrap();
                            &bitwise_or_big_int(&a, black_box(&LARGE_VPRIME_VALUE)).unwrap()
                        },
                        //the commented line below is to see the change in performance when we don't have to generate v and e
                        //black_box(&BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027").unwrap()),
                        black_box(&blinded_cred_secrets_range[i]),
                        black_box(&generate_prime_in_range(&LARGE_E_START_VALUE, &LARGE_E_END_RANGE_VALUE).unwrap())
                        //black_box(&BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881").unwrap())
                    ).unwrap();
                });
            });       
        } sign_group.finish();

    let mut e_range = vec![];
    let mut v_range = vec![];
    let sigs_range = (0..MESSAGE_COUNT_RANGE.len())
        .map(|i|
        Issuer::_sign_primary_credential(
            &credential_pair_range[i].0,
            &credential_pair_range[i].1,
            &credential_context,
            &credential_values_range[i],
            //not sure what dimension for v
            
            { //this now is 3152
                let a = bn_rand(LARGE_VPRIME).unwrap();
                v_range.push(bitwise_or_big_int(&a, &LARGE_VPRIME_VALUE).unwrap());
                &v_range[i]
            },
            //&BigNumber::from_dec("6620937836014079781509458870800001917950459774302786434315639456568768602266735503527631640833663968617512880802104566048179854406925811731340920442625764155409951969854303612644125623549271204625894424804352003689903192473464433927658013251120302922648839652919662117216521257876025436906282750361355336367533874548955283776610021309110505377492806210342214471251451681722267655419075635703240258044336607001296052867746675049720589092355650996711033859489737240617860392914314205277920274997312351322125481593636904917159990500837822414761512231315313922792934655437808723096823124948039695324591344458785345326611693414625458359651738188933757751726392220092781991665483583988703321457480411992304516676385323318285847376271589157730040526123521479652961899368891914982347831632139045838008837541334927738208491424027").unwrap(),
            &blinded_cred_secrets_range[i],
            {
                e_range.push(generate_prime_in_range(&LARGE_E_START_VALUE, &LARGE_E_END_RANGE_VALUE).unwrap());
                &e_range[i]
            }
            //&BigNumber::from_dec("259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742930201588264091397308910346117473868881").unwrap()
        ).unwrap()
        ).collect::<Vec<_>>();

    //verification for a CL sign
    let mut verify_group = c.benchmark_group("ursa CL verifying");
    for (i, (a, _q)) in sigs_range.iter().enumerate() {
        verify_group.bench_with_input(BenchmarkId::from_parameter(MESSAGE_COUNT_RANGE[i]), &i, |b, &i| {
            b.iter(|| 
                assert!(
                    keypair_range[i].0.z.eq({
                        let mut context = black_box(BigNumber::new_context().unwrap());
                        let mut rx = keypair_range[i].0.s.mod_exp(
                            black_box(&v_range[i]), 
                            black_box(&keypair_range[i].0.n), 
                            black_box(Some(&mut context)))
                            .unwrap();
                        //set to 0 so this should never trigger
                        if blinded_cred_secrets_range[i].u != BigNumber::from_u32(0).unwrap() {
                            rx = rx.mod_mul(
                                black_box(&blinded_cred_secrets_range[i].u), 
                                black_box(&keypair_range[i].0.n), 
                                Some(&mut context))
                                .unwrap();
                        }

                        rx = rx.mod_mul(
                            &keypair_range[i].0
                                .rctxt
                                .mod_exp(
                                    black_box(&credential_context), 
                                    black_box(&keypair_range[i].0.n), 
                                    Some(&mut context))
                                    .unwrap(),
                                black_box(&keypair_range[i].0.n),
                            Some(&mut context),
                        ).unwrap();

                        for (key, attr) in credential_values_range[i]
                            .attrs_values
                            .iter()
                            .filter(|&(_, v)| v.is_known())
                        {
                            let pk_r = keypair_range[i].0.r.get(black_box(key)).unwrap();
                            rx = pk_r
                                .mod_exp(
                                    attr.value(), black_box(&keypair_range[i].0.n), Some(&mut context)).unwrap()
                                .mod_mul(&rx, black_box(&keypair_range[i].0.n), Some(&mut context)).unwrap();
                        }
                        &a.mod_exp(
                            black_box(&e_range[i]), 
                            black_box(&keypair_range[i].0.n), 
                            None)
                            .unwrap()
                            .mod_mul(
                                &rx, 
                                black_box(&keypair_range[i].0.n), 
                                Some(&mut context))
                                .unwrap()
                })
                )
            );
        });
    }
    verify_group.finish();   
}

criterion_group!(benches, cl_sign_benchmark);
criterion_main!(benches);
