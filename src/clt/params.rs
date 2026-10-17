use super::SECURITY_BITS;
use crate::class_group::{ClassGroup, Form, pow};
use crate::error::CltError;
use crate::number_theory::{is_probable_prime, kronecker};
use crate::sampling::{DiscreteGaussian, uniform_below};
use ark_ff::{BigInteger, PrimeField};
use ark_std::rand::{CryptoRng, RngCore};
use dashu_int::ops::{BitTest, ExtendedGcd, RemEuclid, SquareRoot, UnsignedAbs};
use dashu_int::{IBig, UBig};
use std::fmt;

#[derive(Clone, Debug)]
pub(crate) struct HsmGroup {
    p: IBig,
    delta_k: IBig,
    group: ClassGroup,
}

#[derive(Clone)]
pub struct Params<F> {
    hsm: HsmGroup,
    generator: Form,
    randomness: DiscreteGaussian,
    key: DiscreteGaussian,
    half: F,
    discriminant_bits: u32,
}

fn is_small_prime(n: u64) -> bool {
    n >= 2 && (2..=n.isqrt()).all(|divisor| !n.is_multiple_of(divisor))
}

fn inverse_mod(value: &IBig, modulus: &IBig) -> IBig {
    let (_, coefficient, _) = value.gcd_ext(modulus);
    IBig::from(coefficient.rem_euclid(modulus))
}

pub(crate) fn class_number_bound(delta_k: &IBig) -> UBig {
    let magnitude = delta_k.unsigned_abs();
    let numerator = UBig::from(2 * magnitude.bit_len()) * (magnitude.sqrt() + UBig::ONE);
    (numerator + UBig::from(8u8)) / UBig::from(9u8)
}

impl HsmGroup {
    pub(crate) fn new(p: IBig, q: IBig) -> Self {
        let delta_k = -(&p * q);
        let group = ClassGroup::new(p.sqr() * &delta_k);
        Self { p, delta_k, group }
    }

    pub(crate) fn group(&self) -> &ClassGroup {
        &self.group
    }

    pub(crate) fn power_of_f(&self, m: &IBig) -> Form {
        let residue = IBig::from(m.rem_euclid(&self.p));
        if residue.is_zero() {
            return self.group.identity();
        }
        let mut lifted = inverse_mod(&residue, &self.p);
        if !lifted.bit(0) {
            lifted -= &self.p;
        }
        Form {
            a: &self.p * &self.p,
            b: &lifted * &self.p,
            c: (lifted.sqr() - &self.delta_k) >> 2,
        }
    }

    pub(crate) fn solve(&self, form: &Form) -> Option<IBig> {
        if form.is_identity() {
            return Some(IBig::ZERO);
        }
        if form.a != &self.p * &self.p {
            return None;
        }
        Some(inverse_mod(&(&form.b / &self.p), &self.p))
    }

    pub(crate) fn generator(&self) -> Form {
        let mut candidate = 2;
        loop {
            if is_small_prime(candidate)
                && let Some(form) = self.group.prime_form(candidate)
            {
                return pow(&self.group, &form, &(&self.p << 1));
            }
            candidate += 1;
        }
    }
}

impl<F: PrimeField> Params<F> {
    pub fn generate(
        discriminant_bits: u32,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self, CltError> {
        let minimum = 2 * F::MODULUS_BIT_SIZE + 3;
        if discriminant_bits < minimum {
            return Err(CltError::DiscriminantTooSmall {
                bits: discriminant_bits,
                minimum,
            });
        }
        let modulus = UBig::from_le_bytes(&F::MODULUS.to_bytes_le());
        let bits = discriminant_bits as usize;
        let low = ((UBig::ONE << (bits - 1)) + &modulus - UBig::ONE) / &modulus;
        let high = ((UBig::ONE << bits) - UBig::ONE) / &modulus;
        let span = high - &low + UBig::ONE;
        let p = IBig::from(modulus.clone());
        let q = loop {
            let candidate = &low + uniform_below(&span, rng);
            if (&modulus * &candidate) % 4u8 == 3
                && kronecker(&p, &IBig::from(candidate.clone())) == -1
                && is_probable_prime(&candidate, rng)
            {
                break candidate;
            }
        };

        let hsm = HsmGroup::new(p, IBig::from(q));
        let randomness_variance = class_number_bound(&hsm.delta_k).sqr() * SECURITY_BITS;
        let key_variance = &randomness_variance * modulus.sqr();
        Ok(Self {
            generator: hsm.generator(),
            hsm,
            randomness: DiscreteGaussian::new(randomness_variance),
            key: DiscreteGaussian::new(key_variance),
            half: F::from_le_bytes_mod_order(&((modulus + UBig::ONE) >> 1).to_le_bytes()),
            discriminant_bits,
        })
    }

    pub fn discriminant_bits(&self) -> u32 {
        self.discriminant_bits
    }

    pub(crate) fn group(&self) -> &ClassGroup {
        self.hsm.group()
    }

    pub(crate) fn power_of_generator(&self, exponent: &IBig) -> Form {
        pow(self.group(), &self.generator, exponent)
    }

    pub(crate) fn encode(&self, message: F) -> Form {
        self.hsm.power_of_f(&Self::lift(message))
    }

    pub(crate) fn sample_randomness(&self, rng: &mut (impl CryptoRng + RngCore)) -> IBig {
        self.randomness.sample(rng)
    }

    pub(crate) fn sample_key(&self, rng: &mut (impl CryptoRng + RngCore)) -> IBig {
        self.key.sample(rng)
    }

    pub(crate) fn decode(&self, form: &Form) -> Result<F, CltError> {
        let doubled = self
            .hsm
            .solve(&self.group().square(form))
            .ok_or(CltError::NotInSubgroup)?;
        Ok(Self::field(&doubled) * self.half)
    }

    pub(crate) fn lift(x: F) -> IBig {
        IBig::from(UBig::from_le_bytes(&x.into_bigint().to_bytes_le()))
    }

    pub(crate) fn field(n: &IBig) -> F {
        let magnitude = F::from_le_bytes_mod_order(&n.unsigned_abs().to_le_bytes());
        if *n < IBig::ZERO {
            -magnitude
        } else {
            magnitude
        }
    }
}

impl<F> fmt::Debug for Params<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Params")
            .field("discriminant_bits", &self.discriminant_bits)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{HsmGroup, Params, class_number_bound};
    use crate::Field128;
    use crate::class_group::pow;
    use crate::class_group::tests::{is_canonical, reduced_forms};
    use crate::error::CltError;
    use crate::number_theory::{is_probable_prime, kronecker};
    use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, UniformRand};
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use dashu_int::ops::{BitTest, UnsignedAbs};
    use dashu_int::{IBig, UBig};

    pub(crate) const TEST_DISCRIMINANT_BITS: u32 = 320;

    pub(crate) fn rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    pub(crate) fn test_params() -> Params<Field128> {
        Params::generate(TEST_DISCRIMINANT_BITS, &mut rng()).unwrap()
    }

    #[test]
    fn toy_hsm_subgroup_round_trips() {
        let hsm = HsmGroup::new(5.into(), 23.into());
        let group = hsm.group();
        let f = hsm.power_of_f(&IBig::ONE);
        let mut power = f.clone();
        let mut order = 1;
        while !power.is_identity() {
            power = group.compose(&power, &f);
            order += 1;
        }
        assert_eq!(order, 5);

        for m in -7i64..=7 {
            let expected = IBig::from(m.rem_euclid(5));
            let m = IBig::from(m);
            let power = hsm.power_of_f(&m);
            assert_eq!(power, pow(group, &f, &m), "{m}");
            assert!(is_canonical(&power, group), "{m}");
            assert_eq!(hsm.solve(&power), Some(expected), "{m}");
        }
        assert_eq!(hsm.solve(&group.prime_form(7).unwrap()), None);
        assert!(is_canonical(&hsm.generator(), group));
    }

    #[test]
    fn class_number_bound_exceeds_class_numbers() {
        for discriminant in [-23, -47, -71, -115] {
            let class_number = reduced_forms(discriminant).len();
            assert!(
                class_number_bound(&discriminant.into()) > UBig::from(class_number),
                "{discriminant}"
            );
        }
    }

    #[test]
    fn generated_parameters_satisfy_cl_conditions() {
        let mut rng = rng();
        let p = IBig::from(UBig::from_le_bytes(&Field128::MODULUS.to_bytes_le()));
        for bits in [259, TEST_DISCRIMINANT_BITS] {
            let params = Params::<Field128>::generate(bits, &mut rng).unwrap();
            assert_eq!(params.discriminant_bits(), bits);
            let hsm = &params.hsm;
            let q = -&hsm.delta_k / &p;
            assert_eq!(&p * &q, -&hsm.delta_k);
            assert!(is_probable_prime(&(&q).unsigned_abs(), &mut rng));
            assert_eq!(-&hsm.delta_k % 4u8, 3);
            assert_eq!(kronecker(&p, &q), -1);
            assert!(q > &p << 2);
            assert_eq!(hsm.delta_k.bit_len(), bits as usize);
            assert_eq!(*hsm.group().discriminant(), p.sqr() * &hsm.delta_k);
            assert!(!params.generator.is_identity());
            assert!(is_canonical(&params.generator, hsm.group()));

            let random = Field128::rand(&mut rng);
            for m in [Field128::ZERO, Field128::ONE, -Field128::ONE, random] {
                let form = params.encode(m);
                assert_eq!(params.decode(&form), Ok(m));
            }
        }
        assert_eq!(
            Params::<Field128>::generate(258, &mut rng).err(),
            Some(CltError::DiscriminantTooSmall {
                bits: 258,
                minimum: 259
            })
        );
    }
}
