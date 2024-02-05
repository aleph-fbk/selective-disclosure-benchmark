use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion,
};
use ursa::bn::BigNumber;
use ursa::cl::constants::{
    LARGE_E_START_VALUE, 
    LARGE_E_END_RANGE_VALUE,
    //LARGE_VPRIME,
};
use ursa::cl::helpers::{
    generate_v_prime_prime, 
    generate_prime_in_range,
    //bn_rand,
};
use ursa::cl::{
    verifier::Verifier, 
    prover::Prover, 
    issuer::Issuer, 
    CredentialSchema, 
    CredentialPublicKey, 
    CredentialPrivateKey, 
    PrimaryCredentialSignature,
    BlindedCredentialSecrets,
    CredentialSignature,
    new_nonce,
};
use std::collections::BTreeSet;

use ursa_benchmark::{
    setup_cl,
    MESSAGE_COUNT_RANGE,
    HARDCODED_HASH,
};

fn cl_proof_benchmark(c:&mut Criterion) {

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
    //we build again a non_credential_schema and a credential_context which will be the same for everything that needs it
    //actually we can leave that struct empty, so we can remove the master_secret
    let non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
    //non_credential_schema_builder.add_attr("master_secret").unwrap();
    let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
    let credential_context = Issuer::_gen_credential_context("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW", None).unwrap();

    //build the signatures
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
            //black_box(&generate_v_prime_prime().unwrap()),
            
            { //this is 2724?
                v_range.push(generate_v_prime_prime().unwrap()); //V_PRIME_PRIME_VALUE
                &v_range[i]
            },
            /*
            { //this now is 3152
                let a = bn_rand(LARGE_VPRIME).unwrap();
                v_range.push(bitwise_or_big_int(&a, &LARGE_VPRIME_VALUE).unwrap());
                &v_range[i]
            },
            */
            &blinded_cred_secrets_range[i],
            {
                e_range.push(generate_prime_in_range(&LARGE_E_START_VALUE, &LARGE_E_END_RANGE_VALUE).unwrap());
                &e_range[i]
            }
        ).unwrap()
        ).collect::<Vec<_>>();

    let mut revealed_indices_range = vec![];
    for (i, count) in MESSAGE_COUNT_RANGE.iter().enumerate() {

        //indicates how many messages we are revealing, from one to number of attributes - 1  
        let mut k = BTreeSet::new();

        //follows a a way to generate a PoK for all different possible number of attributes 
        for j in 0..MESSAGE_COUNT_RANGE[i] {
            k.insert(j);
        }

        let mut revealed_indices = vec![];
        for j in k.iter() {
            let mut ids = BTreeSet::new();
            for l in 0..=*j {
                ids.insert(l);
            }
            revealed_indices.push(ids);
        }
        revealed_indices_range.push(revealed_indices);
        
        let sig = &sigs_range[i];
        //we build a credential_signature in order to process it
        let mut credential_signature = CredentialSignature {
            p_credential: PrimaryCredentialSignature {
                m_2: credential_context.try_clone().unwrap(),
                a: sig.0.try_clone().unwrap(),
                e: e_range[i].try_clone().unwrap(),
                v: v_range[i].try_clone().unwrap(),
                },
                r_credential: None
        };
        //_process_primary_credential() consists in adding the v_prime generated in the blinded_cred_secrets
        //to the v element in the primary credential, it is a necessary step but I am not to sure why (should be part of the credential issuing protocol that we dont want to bench)
        Prover::_process_primary_credential(
            &mut credential_signature.p_credential,
            &v_prime_range[i] //I set this always to 0 
        ).unwrap();
        let mut prove_group = c.benchmark_group(
            format!("ursa CL presentation generation with {} attributes", count));
        for (j, r_count) in k.iter().enumerate() {
            //maybe move out bench done
            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            for ri in revealed_indices_range[i][j].iter() {
                sub_proof_request_builder.add_revealed_attr(&format!("{}", ri)).unwrap();
            }
            let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
            prove_group.bench_with_input(
                BenchmarkId::from_parameter(format!("Revealing {} attributes", r_count + 1)),
                &r_count,
                |b, &_i| {
                    b.iter(|| {
                        //follows what we are benchmarking in this group
                        //we build a sub_proof_request for a variable number of revealed messagge
                        
                        //"master_secret" should be the linked secret hence I leave it like that
                        let mut proof_builder = Prover::new_proof_builder().unwrap();
                        //proof_builder.add_common_attribute("master_secret").unwrap();
                        proof_builder.add_sub_proof_request(
                        black_box(&sub_proof_request),
                        black_box(&credential_schema_range[i]),
                        black_box(&non_credential_schema),
                        black_box(&credential_signature),
                        black_box(&credential_values_range[i]),
                        black_box(&credential_pair_range[i].0),
                        None,
                        None).unwrap();
                        
                        let proof_request_nonce = new_nonce().unwrap();
                        let _ = proof_builder.finalize(&proof_request_nonce).unwrap();
                    });
                },
            );
        }
        prove_group.finish(); 
    } 

    //we redefine everything and store it, we do it outside the bench in order to not measure them
    let mut proof_range = vec![];
    let mut proof_request_nonce_range = vec![];
    let mut sub_proof_request_range = vec![];
    for i in 0..MESSAGE_COUNT_RANGE.len() {
        let mut proofs = vec![];
        let mut proof_request_nonces = vec![];
        let mut sub_proof_requests = vec![];
        let mut credential_signature = CredentialSignature {
            p_credential: PrimaryCredentialSignature {
                m_2: credential_context.try_clone().unwrap(),
                a: sigs_range[i].0.try_clone().unwrap(),
                e: e_range[i].try_clone().unwrap(),
                v: v_range[i].try_clone().unwrap(),
                },
            r_credential: None
        };
        Prover::_process_primary_credential(
            &mut credential_signature.p_credential,
            &v_prime_range[i]
        ).unwrap();
        for j in 0..revealed_indices_range[i].len() {
            let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
            for ri in revealed_indices_range[i][j].iter() {
                sub_proof_request_builder.add_revealed_attr(&format!("{}", ri)).unwrap();
            }
            let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
            let mut proof_builder = Prover::new_proof_builder().unwrap();
            //proof_builder.add_common_attribute("master_secret").unwrap();
            proof_builder.add_sub_proof_request(
            &sub_proof_request,
            &credential_schema_range[i],
            &non_credential_schema,
            &credential_signature,
            &credential_values_range[i],
            &credential_pair_range[i].0,
            None,
            None).unwrap();
            
            let proof_request_nonce = new_nonce().unwrap();
            let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

            proofs.push(proof);
            proof_request_nonces.push(proof_request_nonce);
            sub_proof_requests.push(sub_proof_request);
        }
        proof_range.push(proofs);
        proof_request_nonce_range.push(proof_request_nonces);
        sub_proof_request_range.push(sub_proof_requests);
    }

    for (i, count) in MESSAGE_COUNT_RANGE.iter().enumerate() {
        let mut verify_group = c.benchmark_group(
            format!("ursa CL presentation verification with {} attributes", count));
        for j in 0..revealed_indices_range[i].len() {
            verify_group.bench_with_input(
                BenchmarkId::from_parameter(format!("Revealing {} attributes", revealed_indices_range[i][j].len())),
                &j,
                |b, &_i| {
                    b.iter(|| {
                        //follows what we are benchmarking in this group
                        //which is just a verification of the proof
                        let mut proof_verifier = black_box(Verifier::new_proof_verifier().unwrap());
                        proof_verifier.add_sub_proof_request(black_box(&sub_proof_request_range[i][j]),
                        black_box(&credential_schema_range[i]),
                        black_box(&non_credential_schema),
                        black_box(&credential_pair_range[i].0),
                        None,
                        None).unwrap();
                        assert!(proof_verifier.verify(black_box(&proof_range[i][j]), black_box(&proof_request_nonce_range[i][j])).unwrap());
                    });
                },
            );
        }
        verify_group.finish();   
    }
}

criterion_group!(benches, cl_proof_benchmark);
criterion_main!(benches);
