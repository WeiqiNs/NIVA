use ark_ff::{FftField, Field, PrimeField};
use niva::Field128;

const MODULUS: u128 = (1 << 66) * 4_611_686_018_427_387_897 + 1;
const ODD_FACTORS: [u64; 3] = [3, 3491, 440_340_496_364_689];

fn is_prime(n: u64) -> bool {
    n >= 2 && (2..=n.isqrt()).all(|d| !n.is_multiple_of(d))
}

fn exponent(value: u128) -> impl AsRef<[u64]> {
    Field128::from(value).into_bigint()
}

#[test]
fn field128_parameters() {
    let modulus = Field128::MODULUS.to_string();
    assert_eq!(modulus, "340282366920938462946865773367900766209");
    assert_eq!(modulus, MODULUS.to_string());
    assert_eq!(Field128::TWO_ADICITY, 66);

    let order = MODULUS - 1;
    let odd_part: u128 = ODD_FACTORS
        .iter()
        .map(|&factor| u128::from(factor))
        .product();
    assert_eq!(odd_part << 66, order);
    for factor in ODD_FACTORS {
        assert!(is_prime(factor), "{factor}");
    }

    let generator = Field128::GENERATOR;
    assert_eq!(generator, Field128::from(7u64));
    for factor in [2].into_iter().chain(ODD_FACTORS) {
        let cofactor = order / u128::from(factor);
        assert_ne!(generator.pow(exponent(cofactor)), Field128::ONE, "{factor}");
    }

    let root = Field128::TWO_ADIC_ROOT_OF_UNITY;
    assert_eq!(root.pow(exponent(1 << 65)), -Field128::ONE);
}
