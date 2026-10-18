use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use niva::Field128;
use niva::clt::Params;
use std::sync::Arc;

pub const TEST_DISCRIMINANT_BITS: u32 = 320;

pub fn rng() -> StdRng {
    StdRng::seed_from_u64(11)
}

pub fn params() -> Arc<Params<Field128>> {
    Arc::new(Params::generate(TEST_DISCRIMINANT_BITS, &mut rng()).unwrap())
}
