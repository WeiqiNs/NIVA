use super::ring::Ring;
use crate::Field128;
use crate::error::LatticeError;
use crate::sampling::centered_binomial;
use ark_ff::fields::{Fp192, MontBackend, MontConfig};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, UniformRand};
use ark_std::rand::{CryptoRng, RngCore};
use std::fmt;
use std::iter::Sum;
use std::ops::{Add, Mul, Sub};

pub trait LatticeField: PrimeField + private::Sealed {
    type Headroom: PrimeField;
    const RING_DIMENSION: usize;
}

#[derive(Debug, MontConfig)]
#[modulus = "1427247692705959881058285969449495136382648321"]
#[generator = "3"]
pub struct Headroom150Config;

pub type Headroom150 = Fp192<MontBackend<Headroom150Config, 3>>;

pub struct Lattice<F: LatticeField> {
    field_ring: Ring<F>,
    headroom_ring: Ring<F::Headroom>,
    delta: F,
    delta_inverse: F,
    noise_ceiling: <F::Headroom as PrimeField>::BigInt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Polynomial<F: LatticeField> {
    field: Vec<F>,
    headroom: Vec<F::Headroom>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Residue<F: LatticeField> {
    pub(crate) field: F,
    pub(crate) headroom: F::Headroom,
}

mod private {
    pub trait Sealed {}
}

impl private::Sealed for Field128 {}

impl LatticeField for Field128 {
    type Headroom = Headroom150;
    const RING_DIMENSION: usize = 16384;
}

fn pointwise<K: Copy>(left: &[K], right: &[K], operation: impl Fn(K, K) -> K) -> Vec<K> {
    left.iter()
        .zip(right)
        .map(|(&a, &b)| operation(a, b))
        .collect()
}

fn accumulate<K: PrimeField>(sum: &mut [K], coefficient: K, values: &[K]) {
    for (entry, &value) in sum.iter_mut().zip(values) {
        *entry += coefficient * value;
    }
}

impl<F: LatticeField> Lattice<F> {
    pub fn new(ring_dimension: usize) -> Result<Self, LatticeError> {
        let error = LatticeError::RingDimension {
            dimension: ring_dimension,
        };
        if !(2..=F::RING_DIMENSION).contains(&ring_dimension) {
            return Err(error);
        }
        let (Some(field_ring), Some(headroom_ring)) =
            (Ring::new(ring_dimension), Ring::new(ring_dimension))
        else {
            return Err(error);
        };
        let headroom_modulus = <F::Headroom as PrimeField>::MODULUS;
        let delta = F::from_le_bytes_mod_order(&headroom_modulus.to_bytes_le());
        let fermat_inverse_exponent = (-F::from(2u8)).into_bigint();
        Ok(Self {
            field_ring,
            headroom_ring,
            delta,
            delta_inverse: delta.pow(fermat_inverse_exponent),
            noise_ceiling: headroom_modulus >> 2,
        })
    }

    #[must_use]
    pub fn ring_dimension(&self) -> usize {
        self.field_ring.dimension()
    }

    pub(crate) fn sample_coefficients(&self, rng: &mut (impl CryptoRng + RngCore)) -> Vec<i64> {
        (0..self.ring_dimension())
            .map(|_| centered_binomial(rng))
            .collect()
    }

    pub(crate) fn sample_uniform(&self, rng: &mut (impl CryptoRng + RngCore)) -> Polynomial<F> {
        let dimension = self.ring_dimension();
        Polynomial {
            field: (0..dimension).map(|_| F::rand(rng)).collect(),
            headroom: (0..dimension).map(|_| F::Headroom::rand(rng)).collect(),
        }
    }

    pub(crate) fn forward(&self, coefficients: &[i64]) -> Polynomial<F> {
        Polynomial {
            field: self.field_ring.forward(coefficients),
            headroom: self.headroom_ring.forward(coefficients),
        }
    }

    pub(crate) fn constant_term(&self, left: &Polynomial<F>, right: &Polynomial<F>) -> Residue<F> {
        Residue {
            field: self.field_ring.constant_term(&left.field, &right.field),
            headroom: self
                .headroom_ring
                .constant_term(&left.headroom, &right.headroom),
        }
    }

    pub(crate) fn linear_combination(
        &self,
        coefficients: &[Residue<F>],
        polynomials: &[Polynomial<F>],
    ) -> Polynomial<F> {
        let dimension = self.ring_dimension();
        let mut sum = Polynomial {
            field: vec![F::ZERO; dimension],
            headroom: vec![F::Headroom::ZERO; dimension],
        };
        for (coefficient, polynomial) in coefficients.iter().zip(polynomials) {
            accumulate(&mut sum.field, coefficient.field, &polynomial.field);
            accumulate(
                &mut sum.headroom,
                coefficient.headroom,
                &polynomial.headroom,
            );
        }
        sum
    }

    pub(crate) fn encode(&self, message: F) -> Residue<F> {
        Residue {
            field: message * self.delta,
            headroom: F::Headroom::ZERO,
        }
    }

    pub(crate) fn decode(&self, value: Residue<F>) -> Result<F, LatticeError> {
        Ok((value.field - self.noise(value.headroom)?) * self.delta_inverse)
    }

    fn noise(&self, headroom: F::Headroom) -> Result<F, LatticeError> {
        let magnitude = |value: <F::Headroom as PrimeField>::BigInt| {
            F::from_le_bytes_mod_order(&value.to_bytes_le())
        };
        let positive = headroom.into_bigint();
        if positive <= self.noise_ceiling {
            return Ok(magnitude(positive));
        }
        let negative = (-headroom).into_bigint();
        if negative <= self.noise_ceiling {
            return Ok(-magnitude(negative));
        }
        Err(LatticeError::NoiseTooLarge)
    }
}

impl<F: LatticeField> Residue<F> {
    pub(crate) fn small(value: i64) -> Self {
        Self {
            field: F::from(value),
            headroom: F::Headroom::from(value),
        }
    }

    pub(crate) fn lift(value: F) -> Self {
        let magnitude =
            |value: F| F::Headroom::from_le_bytes_mod_order(&value.into_bigint().to_bytes_le());
        let headroom = if value.into_bigint() <= F::MODULUS_MINUS_ONE_DIV_TWO {
            magnitude(value)
        } else {
            -magnitude(-value)
        };
        Self {
            field: value,
            headroom,
        }
    }
}

impl<F: LatticeField> Add for Residue<F> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            field: self.field + other.field,
            headroom: self.headroom + other.headroom,
        }
    }
}

impl<F: LatticeField> Sub for Residue<F> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self {
            field: self.field - other.field,
            headroom: self.headroom - other.headroom,
        }
    }
}

impl<F: LatticeField> Mul for Residue<F> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self {
            field: self.field * other.field,
            headroom: self.headroom * other.headroom,
        }
    }
}

impl<F: LatticeField> Sum for Residue<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::small(0), Add::add)
    }
}

impl<F: LatticeField> Polynomial<F> {
    pub(crate) fn ring_dimension(&self) -> usize {
        self.field.len()
    }
}

impl<F: LatticeField> Add for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn add(self, other: Self) -> Polynomial<F> {
        Polynomial {
            field: pointwise(&self.field, &other.field, Add::add),
            headroom: pointwise(&self.headroom, &other.headroom, Add::add),
        }
    }
}

impl<F: LatticeField> Mul for &Polynomial<F> {
    type Output = Polynomial<F>;

    fn mul(self, other: Self) -> Polynomial<F> {
        Polynomial {
            field: pointwise(&self.field, &other.field, Mul::mul),
            headroom: pointwise(&self.headroom, &other.headroom, Mul::mul),
        }
    }
}

impl<F: LatticeField> fmt::Debug for Lattice<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lattice")
            .field("ring_dimension", &self.ring_dimension())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Headroom150, Lattice, LatticeField};
    use crate::Field128;
    use crate::error::LatticeError;
    use crate::lattice::MAX_DIMENSION;
    use crate::number_theory::is_probable_prime;
    use crate::sampling::NOISE_ETA;
    use ark_ff::{BigInteger, FftField, Field, PrimeField};
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use dashu_int::UBig;
    use dashu_int::ops::BitTest;

    pub(crate) const TEST_RING_DIMENSION: usize = 1024;

    const HEADROOM_ODD_FACTORS: [u64; 4] =
        [5, 4_010_621, 2_921_482_252_775_351, 743_471_858_316_699_163];

    pub(crate) fn rng() -> StdRng {
        StdRng::seed_from_u64(5)
    }

    pub(crate) fn test_params() -> Lattice<Field128> {
        Lattice::new(TEST_RING_DIMENSION).unwrap()
    }

    pub(crate) fn integer(value: &impl BigInteger) -> UBig {
        UBig::from_le_bytes(&value.to_bytes_le())
    }

    fn log2(value: &impl BigInteger) -> f64 {
        integer(value).to_f64().value().log2()
    }

    #[test]
    fn lattice_parameters_hold() {
        let mut rng = rng();
        let headroom = integer(&Headroom150::MODULUS);
        assert!(is_probable_prime(&headroom, &mut rng));
        assert_eq!(headroom.bit_len(), 150);
        let ring_dimension = Field128::RING_DIMENSION;
        assert!(Headroom150::TWO_ADICITY >= (2 * ring_dimension).ilog2());
        let ciphertext_modulus = integer(&Field128::MODULUS) * &headroom;
        assert!(ciphertext_modulus.bit_len() <= 300);

        let order = &headroom - UBig::ONE;
        let odd_part: UBig = HEADROOM_ODD_FACTORS
            .iter()
            .map(|&f| UBig::from(f))
            .product();
        assert_eq!(odd_part << 15, order);
        let generator = Headroom150::GENERATOR;
        assert_eq!(generator, Headroom150::from(3u8));
        for factor in [2].into_iter().chain(HEADROOM_ODD_FACTORS) {
            let factor = UBig::from(factor);
            assert!(is_probable_prime(&factor, &mut rng), "{factor}");
            let cofactor = Headroom150::from_le_bytes_mod_order(&(&order / &factor).to_le_bytes());
            assert_ne!(
                generator.pow(cofactor.into_bigint()),
                Headroom150::ONE,
                "{factor}"
            );
        }

        let variance = f64::from(NOISE_ETA) / 2.0;
        let worst_case_noise = 9.1f64.log2()
            + log2(&Field128::MODULUS_MINUS_ONE_DIV_TWO)
            + 0.5 * f64::from(u32::try_from(2 * MAX_DIMENSION * ring_dimension).unwrap()).log2()
            + variance.log2();
        assert!(log2(&Headroom150::MODULUS) - 2.0 >= worst_case_noise);

        let params = test_params();
        assert_eq!(params.ring_dimension(), TEST_RING_DIMENSION);
        assert_eq!(
            format!("{params:?}"),
            format!("Lattice {{ ring_dimension: {TEST_RING_DIMENSION}, .. }}")
        );
        assert_eq!(params.delta * params.delta_inverse, Field128::ONE);
        for dimension in [1, 1000, 2 * ring_dimension] {
            assert_eq!(
                Lattice::<Field128>::new(dimension).err(),
                Some(LatticeError::RingDimension { dimension })
            );
        }
        assert!(Lattice::<Field128>::new(ring_dimension).is_ok());
    }
}
