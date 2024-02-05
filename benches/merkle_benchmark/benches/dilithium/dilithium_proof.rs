use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion
};
use rs_merkle::{
    MerkleTree, 
    MerkleProof, 
    algorithms::Sha256, 
    Hasher, 
};
use merkle_benchmark::{
    setup_merkle_oqs,
    MESSAGE_COUNT_RANGE,
};
use oqs::*;

//check order of indices
fn merkle_proof_benchmark(c:&mut Criterion) {

    setup_merkle_oqs!(
        Dilithium2,
        MESSAGE_COUNT_RANGE,
        leaves_range,
        merkle_trees_range,
        keypair_range
    );
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2).unwrap();
    let mut sign_root_range = vec![];
    for i in 0..MESSAGE_COUNT_RANGE.len() {
        //we sign the merkle root
        let merkle_root = merkle_trees_range[i].root().unwrap();
        sign_root_range.push(sigalg.sign(&merkle_root, &keypair_range[i].1).unwrap());
    }
    
    let mut leaf_indices_range = vec![];
    for (i, count) in MESSAGE_COUNT_RANGE.iter().enumerate() {
        let leaf_indices = (0..*count).collect::<Vec<_>>();
        let mut prove_group = c.benchmark_group(
            format!("merkle Dilithium presentation generation with {} attributes", count));
        for indices in leaf_indices.iter() {
            let indices_to_prove = (0..=*indices).collect::<Vec<_>>();
            prove_group.bench_with_input(
                BenchmarkId::from_parameter(format!("Revealing {} attributes", indices + 1)),
                &indices,
                |b, &_i| {
                    b.iter(|| {
                        //follows what we are benchmarking in this group
                        let _leaves_to_prove = black_box(leaves_range[i].get(0..=*indices).unwrap());
                        let _merkle_root = black_box(merkle_trees_range[i].root().unwrap());
                        let merkle_proof = black_box(merkle_trees_range[i].proof(&indices_to_prove));
                        let proof_bytes = black_box(merkle_proof.to_bytes());
                        let _proof = black_box(MerkleProof::<Sha256>::try_from(proof_bytes).unwrap());
                    });
                },
            );
        }
        prove_group.finish(); 
        leaf_indices_range.push(leaf_indices);
    }

    let mut merkle_root_range = vec![];
    let mut proof_range = vec![];
    let mut leaves_to_prove_range = vec![];
    let mut indices_to_prove_range = vec![];

    for (i, _count) in MESSAGE_COUNT_RANGE.iter().enumerate() {
        let mut proofs = vec![];
        let mut leaves_to_proves = vec![];
        let mut indices_to_proves = vec![];

        let merkle_root = merkle_trees_range[i].root().unwrap();
        for indices in leaf_indices_range[i].iter() {
            let indices_to_prove = (0..=*indices).collect::<Vec<_>>();
            let leaves_to_prove = leaves_range[i].get(0..=*indices).unwrap();
            let merkle_proof = merkle_trees_range[i].proof(&indices_to_prove);
            let proof_bytes = merkle_proof.to_bytes();
            let proof = MerkleProof::<Sha256>::try_from(proof_bytes).unwrap();

            proofs.push(proof);
            leaves_to_proves.push(leaves_to_prove);
            indices_to_proves.push(indices_to_prove);
        }
        merkle_root_range.push(merkle_root);
        proof_range.push(proofs);
        leaves_to_prove_range.push(leaves_to_proves);
        indices_to_prove_range.push(indices_to_proves);
    }

    for (i, count) in MESSAGE_COUNT_RANGE.iter().enumerate() {
        let mut verify_group = c.benchmark_group(
            format!("merkle Dilithium presentation verification with {} attributes", count));
            for indices in leaf_indices_range[i].iter() {
            verify_group.bench_with_input(
                BenchmarkId::from_parameter(format!("Revealing {} attributes", indices + 1)),
                &indices,
                |b, &_i| {
                    b.iter(|| {
                        //follows what we are benchmarking in this group
                        //we verify the sign
                        assert!(
                            sigalg.verify(
                                black_box(&merkle_root_range[i]), 
                                black_box(&sign_root_range[i]),
                                black_box(&keypair_range[i].0)
                            )
                                .is_ok()
                            );
                        assert!(
                            proof_range[i][*indices]
                            .verify(
                                black_box(merkle_root_range[i]), 
                                black_box(&indices_to_prove_range[i][*indices]), 
                                black_box(leaves_to_prove_range[i][*indices]), 
                                black_box(leaves_range[i].len()))
                            );
                    });
                },
            );
        }
        verify_group.finish();   
    }
}
criterion_group!(benches, merkle_proof_benchmark);
criterion_main!(benches);
