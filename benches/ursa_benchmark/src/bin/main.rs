use std::collections::BTreeSet;

use zmix::amcl_wrapper::field_elem::FieldElement;
use std::collections::{HashSet};

use zmix::signatures::ps::keys::{keygen as ps_keys_generate, Params};
use zmix::signatures::ps::pok_sig::PoKOfSignature as PSPoKOfSignature;
use zmix::signatures::ps::signature::Signature as PSSignature;
use zmix::signatures::SignatureMessageVector;

fn main() {
    let message_count_range = [5];
    let mut vk_range = vec![];
    let mut attr_range = vec![];
    let mut param_range = vec![];
    let sigs_range = (0..message_count_range.len())
        .map(|i| {
            let attributes: SignatureMessageVector = SignatureMessageVector::random(message_count_range[i]);
            let label = format!("ps sign {} message_count_range[i]", message_count_range[i]);
            let params = Params::new(label.as_bytes());
            let (vk, sk) = ps_keys_generate(message_count_range[i], &params);
            vk_range.push(vk);
            attr_range.push(attributes.clone());
            param_range.push(params.clone());
            PSSignature::new(attributes.as_slice(), &sk, &params).unwrap()
        }
        )
        .collect::<Vec<_>>();

    //println!("SIGNATURE {:#?}\n", sigs_range[0]);
    //println!("PARAMETERS {:#?}\n", param_range[0]);
    //println!("VERIFICATION KEY {:#?}\n", vk_range[0]);



    let mut revealed_indices_range = vec![];
    for (i, _count) in message_count_range.iter().enumerate() {

        let mut k = BTreeSet::new();

        //follows a a way to generate a PoK for all different possible number of attributes 
        for j in 0..message_count_range[i] {
            k.insert(j);
        }

        //useful in BTreeSet format to generate a necessary ProofRequest
        let mut revealed_indices = vec![];
        for j in k.iter() {
            let mut ids = BTreeSet::new();
            for l in 0..=*j {
                ids.insert(l);
            }
            revealed_indices.push(ids);
        }
        revealed_indices_range.push(revealed_indices);
    }
    let mut proof_range = vec![];
    let mut chal_range = vec![];

    for i in 0..message_count_range.len() {
        let sig = &sigs_range[i];

        let mut proofs = vec![];
        let mut chals = vec![];

        for j in 0..revealed_indices_range[i].len() {

            let proof_messages = (0..j)
                .map(|h| {
                    h
                }).collect::<HashSet<_>>();

            let pok = PSPoKOfSignature::init(
                sig,
                &vk_range[i],
                &param_range[i],
                attr_range[i].as_slice(),
                None,
                proof_messages,
            )
            .unwrap();
            let chal = FieldElement::from_msg_hash(&pok.to_bytes());
            let proof = pok.gen_proof(&chal).unwrap();  
            println!("NA {}, ND {}\n",message_count_range[0] ,j); 
            chals.push(chal);
            proofs.push(proof); 
             
        }
        chal_range.push(chals);
        proof_range.push(proofs);      
        
    }
    /* 
    println!("nD, bytes");
    for i in 0..message_count_range.len() {
    for j in 0..proof_range[i].len() {
        println!("{}, {:?}", j + 1, proof_range[i][j].sig.to_bytes().len());
    }}
    */
}