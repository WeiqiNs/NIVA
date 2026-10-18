#![allow(dead_code)]

use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use niva::Field128;
use niva::clt::Clt;
use niva::lattice::Lattice;
use std::sync::Arc;

pub const TEST_DISCRIMINANT_BITS: u32 = 320;
const TEST_RING_DIMENSION: usize = 1024;

pub fn rng() -> StdRng {
    StdRng::seed_from_u64(11)
}

pub fn clt() -> Arc<Clt<Field128>> {
    Arc::new(Clt::generate(TEST_DISCRIMINANT_BITS, &mut rng()).unwrap())
}

pub fn lattice() -> Arc<Lattice<Field128>> {
    Arc::new(Lattice::new(TEST_RING_DIMENSION).unwrap())
}

pub fn inner_product(x: &[Field128], y: &[Field128]) -> Field128 {
    x.iter().zip(y).map(|(a, b)| *a * b).sum()
}
