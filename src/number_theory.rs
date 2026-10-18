use crate::sampling::uniform_below;
use ark_std::rand::{CryptoRng, RngCore};
use dashu_int::monty::MontgomeryRepr;
use dashu_int::ops::{BitTest, RemEuclid, UnsignedAbs};
use dashu_int::{IBig, UBig};

const PRIMALITY_ROUNDS: u32 = 40;
const TRIAL_DIVISION_BOUND: u32 = 64;

fn two_symbol(odd: &impl BitTest) -> i8 {
    if odd.bit(1) == odd.bit(2) { 1 } else { -1 }
}

pub(crate) fn kronecker(a: &IBig, n: &IBig) -> i8 {
    let mut modulus = n.unsigned_abs();
    if modulus.is_zero() {
        return i8::from(a.unsigned_abs().is_one());
    }
    let mut symbol = if *n < IBig::ZERO && *a < IBig::ZERO {
        -1
    } else {
        1
    };
    while !modulus.bit(0) {
        if !a.bit(0) {
            return 0;
        }
        modulus >>= 1;
        symbol *= two_symbol(a);
    }

    let mut residue = a.rem_euclid(IBig::from(modulus.clone()));
    loop {
        if residue.is_zero() {
            return if modulus.is_one() { symbol } else { 0 };
        }
        while !residue.bit(0) {
            residue >>= 1;
            symbol *= two_symbol(&modulus);
        }
        if residue.bit(1) && modulus.bit(1) {
            symbol = -symbol;
        }
        (residue, modulus) = (&modulus % &residue, residue);
    }
}

fn passes_miller_rabin(n: &UBig, base: &UBig) -> bool {
    let ring = MontgomeryRepr::new(n.clone());
    let minus_one = ring.reduce(n - UBig::ONE);
    let mut odd_part = n - UBig::ONE;
    let mut squarings = 0;
    while !odd_part.bit(0) {
        odd_part >>= 1;
        squarings += 1;
    }

    let mut power = ring.reduce(base.clone()).pow(&odd_part);
    if power == ring.reduce(UBig::ONE) || power == minus_one {
        return true;
    }
    for _ in 1..squarings {
        power = power.sqr();
        if power == minus_one {
            return true;
        }
    }
    false
}

pub(crate) fn is_probable_prime(n: &UBig, rng: &mut (impl CryptoRng + RngCore)) -> bool {
    if *n < UBig::from(2u8) {
        return false;
    }
    for divisor in 2..TRIAL_DIVISION_BOUND {
        if n % divisor == 0 {
            return *n == UBig::from(divisor);
        }
    }
    let random_base_bound = n - UBig::from(3u8);
    passes_miller_rabin(n, &UBig::from(2u8))
        && (0..PRIMALITY_ROUNDS).all(|_| {
            let base = uniform_below(&random_base_bound, rng) + UBig::from(2u8);
            passes_miller_rabin(n, &base)
        })
}

#[cfg(test)]
mod tests {
    use super::{is_probable_prime, kronecker};
    use crate::Field128;
    use ark_ff::{BigInteger, PrimeField};
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use dashu_int::{IBig, UBig};

    fn sieve(limit: usize) -> Vec<bool> {
        let mut prime = vec![true; limit];
        prime[0] = false;
        prime[1] = false;
        for n in 2..=limit.isqrt() {
            if prime[n] {
                for multiple in (n * n..limit).step_by(n) {
                    prime[multiple] = false;
                }
            }
        }
        prime
    }

    fn euler_criterion(a: i64, p: i64) -> i8 {
        let base = a.rem_euclid(p);
        let mut power = 1;
        for _ in 0..(p - 1) / 2 {
            power = power * base % p;
        }
        match power {
            0 => 0,
            1 => 1,
            _ => -1,
        }
    }

    fn symbol(a: i64, n: i64) -> i8 {
        kronecker(&IBig::from(a), &IBig::from(n))
    }

    #[test]
    fn kronecker_matches_reference_values() {
        let primes = sieve(200);
        for p in (3..200).filter(|&p| primes[p]) {
            let p = i64::try_from(p).unwrap();
            for a in -p..2 * p {
                assert_eq!(symbol(a, p), euler_criterion(a, p), "({a}/{p})");
            }
        }

        let nonzero = (-30..=30).filter(|&n| n != 0);
        for a in -30..=30 {
            for m in nonzero.clone() {
                for n in nonzero.clone() {
                    assert_eq!(symbol(a, m * n), symbol(a, m) * symbol(a, n), "{a} {m} {n}");
                }
            }
        }

        let table = [
            (1, 2, 1),
            (7, 2, 1),
            (-1, 2, 1),
            (3, 2, -1),
            (5, 2, -1),
            (-3, 2, -1),
            (4, 2, 0),
            (3, 12, 0),
            (5, -1, 1),
            (-5, -1, -1),
            (0, -1, 1),
            (-3, -7, -1),
            (5, -7, -1),
            (2, -7, 1),
            (1, 0, 1),
            (-1, 0, 1),
            (2, 0, 0),
            (0, 0, 0),
        ];
        for (a, n, expected) in table {
            assert_eq!(symbol(a, n), expected, "({a}/{n})");
        }
    }

    #[test]
    fn primality_matches_sieve_and_rejects_pseudoprimes() {
        let mut rng = StdRng::seed_from_u64(3);
        let primes = sieve(10_000);
        for (n, &expected) in primes.iter().enumerate() {
            assert_eq!(is_probable_prime(&UBig::from(n), &mut rng), expected, "{n}");
        }

        let carmichael = [561u64, 1105, 1729, 2465, 2821, 6601, 8911];
        let strong_base_two_pseudoprime = 3_215_031_751;
        for n in carmichael.into_iter().chain([strong_base_two_pseudoprime]) {
            assert!(!is_probable_prime(&UBig::from(n), &mut rng), "{n}");
        }

        let mersenne = (UBig::ONE << 127) - UBig::ONE;
        let field_modulus = UBig::from_le_bytes(&Field128::MODULUS.to_bytes_le());
        for prime in [mersenne, field_modulus] {
            assert!(is_probable_prime(&prime, &mut rng), "{prime}");
        }
    }
}
