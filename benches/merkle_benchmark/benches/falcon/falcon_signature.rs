use criterion::{
    black_box, 
    criterion_group, 
    criterion_main, 
    BenchmarkId, 
    Criterion
};
use rs_merkle::{
    MerkleTree, 
    algorithms::Sha256, 
    Hasher, 
};
use merkle_benchmark::{
    setup_merkle_oqs,
    MESSAGE_COUNT_RANGE,
};
use oqs::*;

fn merkle_sign_benchmark(c:&mut Criterion) {

    //setup the messages and the keypairs, and a lot of necessary stuff
    setup_merkle_oqs!(
        Falcon512,
        MESSAGE_COUNT_RANGE, 
        leaves_range,
        merkle_trees_range,
        keypair_range
    );

    let sigalg = sig::Sig::new(sig::Algorithm::Falcon512).unwrap();
    let mut sign_group = c.benchmark_group("merkle Falcon signing");
        for (i, count) in MESSAGE_COUNT_RANGE.iter().enumerate() {
            sign_group.bench_with_input(
                BenchmarkId::from_parameter(*count),
                &i, 
                |b, &i| { b.iter(|| {
                    //follows bench
                    //we build the merkle tree from the leaves
                    let mt = MerkleTree::<Sha256>::from_leaves(black_box(&leaves_range[i]));
                    //sign the root
                    let mr = black_box(mt.root().unwrap());
                    let _signature = sigalg.sign(&mr, &keypair_range[i].1).unwrap();
                });
            });       
        } sign_group.finish();

    //sign all mr
    let mut sign_root_range = vec![];
    let mut mr_range = vec![];
    for i in 0..MESSAGE_COUNT_RANGE.len() {
        //we sign the merkle root
        let merkle_root = merkle_trees_range[i].root().unwrap();
        sign_root_range.push(sigalg.sign(&merkle_root, &keypair_range[i].1).unwrap());
        mr_range.push(merkle_root);
    }
    //verification
    let mut verify_group = c.benchmark_group("merkle Falcon verifying");
    for (i, sr) in sign_root_range.iter().enumerate() {
        verify_group.bench_with_input(BenchmarkId::from_parameter(MESSAGE_COUNT_RANGE[i]), &i, |b, &i| {
            b.iter(|| {
                assert!(
                    sigalg.verify(
                        black_box(&mr_range[i]), 
                        black_box(sr),
                        black_box(&keypair_range[i].0)
                    )
                        .is_ok()
                    );
                //root ver? To me it seems that the holder needs to build again a mt and verify the root in that way
                assert_eq!(
                    MerkleTree::<Sha256>::from_leaves(black_box(&leaves_range[i])).root().unwrap(),
                    mr_range[i]
                );
            }
            );
        });
    }
    verify_group.finish();   
}

criterion_group!(benches, merkle_sign_benchmark);
criterion_main!(benches);