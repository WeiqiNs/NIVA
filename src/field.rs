use ark_ff::fields::{Fp128, MontBackend, MontConfig};

#[derive(Debug, MontConfig)]
#[modulus = "340282366920938462946865773367900766209"]
#[generator = "7"]
pub struct Field128Config;

pub type Field128 = Fp128<MontBackend<Field128Config, 2>>;
