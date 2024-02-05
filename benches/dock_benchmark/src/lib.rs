pub const MCR: &'static [usize] = &[2, 4, 8, 16, 33];
// need to have both in usize and u32 to avoid conversions, ugly I know
pub const MCRU32: &'static [u32] = &[2, 4, 8, 16, 33];

pub const STEP:usize = 4;

#[macro_export]
macro_rules! setup_bbs_plus {
    ($sig_params:ident, $keypair: ident, $rng: ident, $message_count_range: ident, $messages_range: ident, $params_range: ident, $keypair_range: ident, $kp_gen_func: ident) => {
        let $messages_range = $message_count_range
            .iter()
            .map(|c| {
                (0..*c)
                    .into_iter()
                    .map(|_| Fr::rand(&mut $rng))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let $params_range = $message_count_range
            .iter()
            .map(|c| $sig_params::<Bls12_381>::generate_using_rng(&mut $rng, *c))
            .collect::<Vec<_>>();
        let $keypair_range = $params_range
            .iter()
            .map(|p| $keypair::<Bls12_381>::$kp_gen_func(&mut $rng, p))
            .collect::<Vec<_>>();
    };
}
