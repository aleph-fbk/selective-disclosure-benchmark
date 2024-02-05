use bn::{BigNumber, BIGNUMBER_2};

pub const LARGE_MASTER_SECRET: usize = 256; 
pub const LARGE_E_START: usize = 596; //no var
pub const LARGE_E_END_RANGE: usize = 119; //no var
pub const LARGE_PRIME: usize = 1536;//1024;
pub const LARGE_VPRIME: usize = 3152; //2128;
pub const LARGE_VPRIME_PRIME: usize = 3748; //2724; //no var 
pub const LARGE_MVECT: usize = 592;
pub const LARGE_ETILDE: usize = 456;
pub const LARGE_VTILDE: usize = 4084; //3748; //3060;
pub const LARGE_UTILDE: usize = 592; //no var
pub const LARGE_MTILDE: usize = 593;
pub const LARGE_VPRIME_TILDE: usize = 673; //this should be v_dash_prime, so I leave it like that, otherwise 3488;
pub const LARGE_RTILDE: usize = 672; //no var
pub const ITERATION: usize = 4;

/*
  LARGE_M1_TILDE: now it differs from the paper v0.3, but author of the paper,
  Dmitry Khovratovich, suggests to use same size as LARGE_MVECT
  FIXME sync the paper and remove this comment
*/
pub const LARGE_NONCE: usize = 80; // number of bits
pub const LARGE_ALPHATILDE: usize = 2787; //no var

// Constants that are used throughout the CL signatures code, so avoiding recomputation.
lazy_static! {
    pub static ref LARGE_E_START_VALUE: BigNumber = BIGNUMBER_2
        .exp(&BigNumber::from_u32(LARGE_E_START).unwrap(), None)
        .unwrap();
    pub static ref LARGE_E_END_RANGE_VALUE: BigNumber = BIGNUMBER_2
        .exp(&BigNumber::from_u32(LARGE_E_END_RANGE).unwrap(), None)
        .unwrap()
        .add(&LARGE_E_START_VALUE)
        .unwrap();
    pub static ref LARGE_VPRIME_PRIME_VALUE: BigNumber = BIGNUMBER_2
        .exp(&BigNumber::from_u32(LARGE_VPRIME_PRIME - 1).unwrap(), None)
        .unwrap();
    pub static ref LARGE_VPRIME_VALUE: BigNumber = BIGNUMBER_2
        .exp(&BigNumber::from_u32(LARGE_VPRIME - 1).unwrap(), None)
        .unwrap();
}
