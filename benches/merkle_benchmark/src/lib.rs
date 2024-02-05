// MESSAGE_COUNT_RANGE indicates the number of attributes used to build a signature
pub const MESSAGE_COUNT_RANGE: &'static [usize] = &[2, 4, 8, 16, 33];

#[macro_export]
macro_rules! setup_merkle {(
    $messages_count_range:ident, 
    $leaves_range:ident,
    $merkle_trees_range:ident,
    $keypair_range:ident
    ) => {
        //macro that setup a range of merkle trees
        let $leaves_range = $messages_count_range
        .iter()
        .map(|m| {
            (0..*m)
                .map(|i| Sha256::hash(i.to_string().as_bytes()))
                .collect::<Vec<[u8; 32]>>()
            })
            .collect::<Vec<_>>();

        let $merkle_trees_range = $leaves_range
            .iter()
            .map(|leaves| MerkleTree::<Sha256>::from_leaves(&leaves))
            .collect::<Vec<_>>();

        let mut $keypair_range = vec![];
        for i in 0..$messages_count_range.len() {
            let mut rng = rand::thread_rng();
            $keypair_range.push(Keypair::generate(&mut rng));
        }
            
    };
}

#[macro_export]
macro_rules! setup_merkle_oqs {(
    $algo:ident,
    $messages_count_range:ident, 
    $leaves_range:ident,
    $merkle_trees_range:ident,
    $keypair_range:ident
    ) => {
        //macro that setup a range of merkle trees
        let $leaves_range = $messages_count_range
        .iter()
        .map(|m| {
            (0..*m)
                .map(|i| Sha256::hash(i.to_string().as_bytes()))
                .collect::<Vec<[u8; 32]>>()
            })
            .collect::<Vec<_>>();

        let $merkle_trees_range = $leaves_range
            .iter()
            .map(|leaves| MerkleTree::<Sha256>::from_leaves(&leaves))
            .collect::<Vec<_>>();

        let mut $keypair_range = vec![];
        for i in 0..$messages_count_range.len() {
            let sigalg = sig::Sig::new(sig::Algorithm::$algo).unwrap();
            $keypair_range.push(sigalg.keypair().unwrap());
        }
            
    };
}
