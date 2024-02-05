// MESSAGE_COUNT_RANGE indicates the number of attributes used to build a signature
pub const MESSAGE_COUNT_RANGE: &'static [usize] = &[2, 4, 8, 16, 33];

#[macro_export]
macro_rules! setup_bbs {(
        $messages_range:ident, 
        $message_count_range:ident, 
        $keypair_range:ident
    ) => {
        //macro that setup bbs keys with a certain range of attributes that are expected in a form [0], [1], ...
        let $messages_range = $message_count_range
            .iter()
            .map(|m| {
                (0..*m)
                    .map(|i| {
                        SignatureMessage::hash(i.to_string().as_bytes())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        
        let $keypair_range = $message_count_range
            .iter()
            .map(|m| Issuer::new_keys(*m).unwrap())
            .collect::<Vec<_>>();
    };
}

#[macro_export]
macro_rules! setup_cl {(
        $messages_range:ident,
        $message_count_range:ident,
        $keypair_range:ident, 
        $credential_pair_range:ident, 
        $credential_values_range:ident, 
        $credential_schema_range:ident,
        $blinded_cred_secrets_range:ident,
        $v_prime_range:ident
    ) => {
        //macro that setup cl keys with a certain range of attributes that are expected in a form [0], [1], ...
        let $messages_range = $message_count_range
            .iter()
            .map(|m| {
                (0..*m)
                    .map(|i| format!("{}", i))
                    .collect::<BTreeSet<_>>()
            })
            .collect::<Vec<_>>();
        
        let mut $credential_schema_range = $messages_range
            .iter()
            .map(|m| CredentialSchema {
                    attrs: m.clone() //attr names
                }).collect::<Vec<_>>();

        //seems to be necessary, I dont fully understand what a non_credential is tbh
        let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
        //non_credential_schema_builder.add_attr("master_secret").unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
        
        //it is a matrioska of required types 
        //main difference between keypair and credential_pair is for the revocation, hence for us are basically the same thing
        //but we have to build both for types requirement
        let $keypair_range = $credential_schema_range
            .iter()
            //primary stuff should be the core without the blinding etc.
            .map(|cs| Issuer::_new_credential_primary_keys(&cs, &non_credential_schema).unwrap())
            .collect::<Vec<_>>();

        let $credential_pair_range = $keypair_range
            .iter()
            .map(|kp| (CredentialPublicKey {
                p_key: kp.0.try_clone().unwrap(),
                r_key: None
            },
            CredentialPrivateKey {
                p_key: kp.1.try_clone().unwrap(),
                r_key: None
            })
        ).collect::<Vec<_>>();

        //we need to tell that the paramenters are all known for both Prover and Issuer
        //credential values are useful to compute stuff on, we expect for example "born", "1997"
        //for some reasons "1997" is stored as a BigNumber, that made me quite a lot confuse
        let mut $credential_values_range = vec![];
        let mut hidden_attributes = BTreeSet::<String>::new();
        //hidden_attributes.insert(String::from("master_secret"));
        let mut $blinded_cred_secrets_range = vec![];
        let mut $v_prime_range = vec![];
        for i in 0..$message_count_range.len() {
            //let master_secret = Prover::new_master_secret().unwrap();
            let credential_nonce = new_nonce().unwrap();
            let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
            //credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap()).unwrap();
            let mut h = 0;
            for value in $credential_schema_range[i].attrs.clone() {
                //let cv = BigNumber::rand(256).unwrap().to_dec().unwrap(); //random number of 256 bits
                /*
                let cv = BigNumber::from_dec(
                    "115792089237316195423570985008687907853269984665640564039457584007913129639936" //2^256
                ).unwrap().rand_range().unwrap().to_dec().unwrap(); //random number up to 256 bits
                */
                let cv = BigNumber::from_hex(HARDCODED_HASH[h]).unwrap().to_dec().unwrap();
                //println!("{:?}", &cv);
                credential_values_builder.add_dec_known(&value, &cv).unwrap();
                h += 1;
            }
            let credential_values = credential_values_builder.finalize().unwrap();
            $credential_values_range.push(credential_values);
            let primary_blinded_cred_secrets = Prover::_generate_blinded_primary_credential_secrets_factors(
                &$keypair_range[i].0,
                &$credential_values_range[i]
            ).unwrap();
            let blinded_cred_secrets = BlindedCredentialSecrets {
                //u: primary_blinded_cred_secrets.u, //this is a random LARGE_VPRIME, it is most notably used in _process_primary_credential(), where it is added to the already existing random v value of the primary credential
                u: BigNumber::from_u32(0).unwrap(),
                ur: None, //for revoc which we are not using
                hidden_attributes: primary_blinded_cred_secrets.hidden_attributes, //this is empty
                committed_attributes: primary_blinded_cred_secrets.committed_attributes //this should always be empty
            };
            $blinded_cred_secrets_range.push(blinded_cred_secrets);
            $v_prime_range.push(BigNumber::from_u32(0).unwrap());
        }
    };
}

pub const HARDCODED_HASH: &'static [&str] = &[
    "0c70c38ad944edeffb2f713e76e8ba3a1554d13ebb05ebd08cfe3e5eba33a437",
    "4fcd1a6c8e438aa9fcccacd2acc3da23f368e610429f6da4d7bd8c03130041f2",
    "4d6f6961f2b86723ea9bf309369e7ad7911af328e63287d9fa34b080d72df988",
    "530ba9a9e0674e20fba9e802fd2fa9763ae54092aa3fa1516d9a0f37162d24b5",
    "621055fa5ce6d53ac0e43e2887bca152e2c147f7b2870ecff95e3e954aeb4244",
    "1e0e14e12816809c4af5e9109cd25c8dad5704fc8ede82aaacf7d3d5933768fc",
    "5a36ce1450735c2cab1cd61671b3f21631643c1b5ed0aaa84e2c4b290546b020",
    "26f268f9dab367aa95367673b0413c3af8892c7a1299d029163a847352ec7dda",
    "3541d37149a3925b453763945d591e784b9cf305ddf639753fa1cfcd9b0d68a2",
    "5da12218bda9f1a3907b5197767117199759cfac78abeb6e178d97437d8b7760",
    "51f1585af931ca862b0a4c63eac32974cd4fc6ff67d29378887202ee9afb9294",
    "2e7d979034ee86befaf4556e04eb1b1c8917c58509ad948800149aa74fe9a5e7",
    "5782817d1d2f71b6c47cb0426a526d613fffdaa6fd3546dc75a0712b82a941bd",
    "1f84fb247d232acaa10a1bd760f4d5643c6c29efe4b3ef5b7d482721b6b84b82",
    "1961f59da7c36e7f49d2905d2830a3dcef1c21c5757dc77c45e98e0e73b11c0e",
    "3144b95d568daa09f8b16ecabe24533398c2aaedc4b6c121d76c1ea85184b35c",
    "53e6931c56566cd74ea5bd63248f921a814ece5ec798c133a05455e3ebf281c0",
    "5d68609e361636993957e0c1ccfe28022be8d8be1eb67c06a4c3f22da29f0902",
    "30a387a8ecc4592b2e928701bbf4ce3ddd00eb1fd21edff20baa419b769f864c",
    "6f0e0d707a2ed0c71b0f1798a7f0ec6163315f614c961b6d850cef55c254bb17",
    "14cc9dbd17d3a939fd0b0f8bf4b0318694db0d4f122a7316ff633138c017d838",
    "51d37f829fece9e6c36399e66dc5366c80cbffb3f940ca4f23a4d36871399ba7",
    "3274ebbae707c999cb108ae6b56f5df55a69a89be0b14b58e4753d4d6cb507e2",
    "1fdf5ecf980588fdc075db63871473b46dfbbea8962d1fd1f6025852f4635de7",
    "14e1fe67d82c6a317f37d397d9bd2ad5266f59e64afb7582217396066207cd4e",
    "49c8647687f6c3cb30fdf967cc238738351cf382ff25c900a66bd59a070802c0",
    "0ad4f7d1b48c61a688fa123975c1eb9d81b211b373cbd8b7a088deaff0f31717",
    "356f94941240dcded9538e4bfbf16292838f8282e3dba2e2bbd5862d0c2c6c64",
    "22608a382314a8c0282bdbf779acee003202fdec31cb3a9d83eea94ff1f006ed",
    "68c9723d9451c017709e1ca3fb82718ff75c0a3148bb4520b944542293235d2d",
    "1796a06df3dbf365e5e2bbd4718501af901b6a78e74d6e950b4a978cdeb34378",
    "090c1631a9c0aedcbb8ed1d206e2533854aa4d52da6ca57dd8e9cfb2cbfd94bb",
    "6adbfd8994a2de2abf55cfd010920f0806c77d09933cd32d85b2823d4412d86c",
];
