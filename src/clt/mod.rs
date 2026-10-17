mod params;

pub use params::Params;

use crate::class_group::{Form, pow};
use crate::error::CltError;
use ark_ff::{Field, PrimeField};
use ark_std::rand::{CryptoRng, RngCore};
use dashu_int::IBig;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

pub const SECURITY_BITS: u32 = 128;
pub const DISCRIMINANT_BITS: u32 = 1827;

#[derive(Clone, Debug)]
pub struct PublicKey<F> {
    params: Arc<Params<F>>,
    bases: Vec<Form>,
}

pub struct MasterSecretKey<F> {
    params: Arc<Params<F>>,
    exponents: Vec<IBig>,
}

#[derive(Clone, Debug)]
pub struct FunctionKey<F> {
    coeffs: Vec<IBig>,
    secret: IBig,
    _field: PhantomData<F>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext<F> {
    randomness: Form,
    coords: Vec<Form>,
    _field: PhantomData<F>,
}

fn check_dimension(expected: usize, actual: usize) -> Result<(), CltError> {
    if expected != actual {
        return Err(CltError::DimensionMismatch { expected, actual });
    }
    Ok(())
}

fn check_prefix(len: usize, dimension: usize) -> Result<(), CltError> {
    if len > dimension {
        return Err(CltError::PrefixTooLong { len, dimension });
    }
    Ok(())
}

fn linearly_independent<F: Field>(vectors: &[&[F]]) -> bool {
    let mut rows: Vec<Vec<F>> = vectors.iter().map(|vector| vector.to_vec()).collect();
    let columns = rows.first().map_or(0, Vec::len);
    let mut rank = 0;
    for column in 0..columns {
        let Some(offset) = rows[rank..].iter().position(|row| !row[column].is_zero()) else {
            continue;
        };
        rows.swap(rank, rank + offset);
        let (done, rest) = rows.split_at_mut(rank + 1);
        let pivot_row = &done[rank];
        for row in rest {
            let factor = row[column];
            for (entry, &pivot_entry) in row.iter_mut().zip(pivot_row) {
                *entry = *entry * pivot_row[column] - factor * pivot_entry;
            }
        }
        rank += 1;
    }
    rank == rows.len()
}

pub fn setup<F: PrimeField>(
    params: &Arc<Params<F>>,
    dimension: usize,
    rng: &mut (impl CryptoRng + RngCore),
) -> (PublicKey<F>, MasterSecretKey<F>) {
    let exponents: Vec<IBig> = (0..dimension).map(|_| params.sample_key(rng)).collect();
    let bases = exponents
        .iter()
        .map(|exponent| params.power_of_generator(exponent))
        .collect();
    (
        PublicKey {
            params: Arc::clone(params),
            bases,
        },
        MasterSecretKey {
            params: Arc::clone(params),
            exponents,
        },
    )
}

impl<F: PrimeField> PublicKey<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.bases.len()
    }

    pub fn encrypt(
        &self,
        message: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Ciphertext<F>, CltError> {
        check_dimension(self.dimension(), message.len())?;
        Ok(self.encrypt_unchecked(message, rng))
    }

    pub(crate) fn encrypt_unchecked(
        &self,
        message: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Ciphertext<F> {
        let params = &self.params;
        let group = params.group();
        let randomness = params.sample_randomness(rng);
        let coords = message
            .iter()
            .zip(&self.bases)
            .map(|(&value, base)| {
                group.compose(&params.encode(value), &pow(group, base, &randomness))
            })
            .collect();
        Ciphertext {
            randomness: params.power_of_generator(&randomness),
            coords,
            _field: PhantomData,
        }
    }

    pub fn eval(&self, key: &FunctionKey<F>, ciphertext: &Ciphertext<F>) -> Result<F, CltError> {
        check_dimension(key.coeffs.len(), ciphertext.dimension())?;
        let group = self.params.group();
        let unmasked = ciphertext.coords.iter().zip(&key.coeffs).fold(
            pow(group, &ciphertext.randomness, &-&key.secret),
            |product, (coord, coeff)| group.compose(&product, &pow(group, coord, coeff)),
        );
        self.params.decode(&unmasked)
    }

    pub fn add(
        &self,
        left: &Ciphertext<F>,
        right: &Ciphertext<F>,
    ) -> Result<Ciphertext<F>, CltError> {
        check_dimension(left.dimension(), right.dimension())?;
        Ok(self.add_unchecked(left, right))
    }

    pub(crate) fn add_unchecked(
        &self,
        left: &Ciphertext<F>,
        right: &Ciphertext<F>,
    ) -> Ciphertext<F> {
        let group = self.params.group();
        Ciphertext {
            randomness: group.compose(&left.randomness, &right.randomness),
            coords: left
                .coords
                .iter()
                .zip(&right.coords)
                .map(|(left, right)| group.compose(left, right))
                .collect(),
            _field: PhantomData,
        }
    }

    pub fn prefix(&self, len: usize) -> Result<Self, CltError> {
        check_prefix(len, self.dimension())?;
        Ok(Self {
            params: Arc::clone(&self.params),
            bases: self.bases[..len].to_vec(),
        })
    }
}

impl<F: PrimeField> MasterSecretKey<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.exponents.len()
    }

    pub fn function_keys(&self, vectors: &[&[F]]) -> Result<Vec<FunctionKey<F>>, CltError> {
        for vector in vectors {
            check_dimension(self.dimension(), vector.len())?;
        }
        if !linearly_independent(vectors) {
            return Err(CltError::DependentFunctionVectors);
        }
        Ok(vectors
            .iter()
            .map(|vector| {
                let coeffs: Vec<IBig> = vector.iter().map(|&value| Params::lift(value)).collect();
                let secret = coeffs
                    .iter()
                    .zip(&self.exponents)
                    .map(|(coeff, exponent)| coeff * exponent)
                    .sum();
                FunctionKey {
                    coeffs,
                    secret,
                    _field: PhantomData,
                }
            })
            .collect())
    }

    pub fn decrypt(&self, ciphertext: &Ciphertext<F>) -> Result<Vec<F>, CltError> {
        check_dimension(self.dimension(), ciphertext.dimension())?;
        let group = self.params.group();
        ciphertext
            .coords
            .iter()
            .zip(&self.exponents)
            .map(|(coord, exponent)| {
                let mask = pow(group, &ciphertext.randomness, &-exponent);
                self.params.decode(&group.compose(coord, &mask))
            })
            .collect()
    }

    pub fn prefix(&self, len: usize) -> Result<Self, CltError> {
        check_prefix(len, self.dimension())?;
        Ok(Self {
            params: Arc::clone(&self.params),
            exponents: self.exponents[..len].to_vec(),
        })
    }
}

impl<F> fmt::Debug for MasterSecretKey<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterSecretKey")
            .field("dimension", &self.exponents.len())
            .finish_non_exhaustive()
    }
}

impl<F> Ciphertext<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.coords.len()
    }

    pub fn prefix(mut self, len: usize) -> Result<Self, CltError> {
        check_prefix(len, self.dimension())?;
        self.coords.truncate(len);
        Ok(self)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) use super::params::tests::{rng, test_params};
    use super::{Ciphertext, MasterSecretKey, PublicKey, setup};
    use crate::Field128;
    use crate::error::CltError;
    use ark_ff::{BigInteger, PrimeField, UniformRand};
    use dashu_int::{IBig, UBig};
    use std::sync::Arc;

    fn keys(dimension: usize) -> (PublicKey<Field128>, MasterSecretKey<Field128>) {
        setup(&Arc::new(test_params()), dimension, &mut rng())
    }

    fn message(len: usize) -> Vec<Field128> {
        let mut rng = rng();
        (0..len).map(|_| Field128::rand(&mut rng)).collect()
    }

    #[test]
    fn secret_key_has_negative_exponents_and_round_trips() {
        let (public_key, secret_key) = keys(16);
        assert!(
            secret_key
                .exponents
                .iter()
                .any(|exponent| *exponent < IBig::ZERO)
        );
        let message = message(16);
        let ciphertext = public_key.encrypt(&message, &mut rng()).unwrap();
        assert_eq!(secret_key.decrypt(&ciphertext), Ok(message));
    }

    #[test]
    fn two_torsion_tampering_decodes_as_untampered() {
        let (public_key, secret_key) = keys(3);
        let params = &public_key.params;
        let group = params.group();
        let p = IBig::from(UBig::from_le_bytes(&Field128::MODULUS.to_bytes_le()));
        let p_cubed = &p * &p * &p;
        let torsion = group.reduced(p_cubed.clone(), p_cubed);
        assert!(!torsion.is_identity());
        assert!(group.square(&torsion).is_identity());

        let message = message(3);
        let ciphertext = public_key.encrypt(&message, &mut rng()).unwrap();
        let mut tampered: Ciphertext<Field128> = ciphertext.clone();
        tampered.randomness = group.compose(&tampered.randomness, &torsion);
        tampered.coords[0] = group.compose(&tampered.coords[0], &torsion);
        assert_ne!(tampered, ciphertext);

        let key = &secret_key.function_keys(&[message.as_slice()]).unwrap()[0];
        assert_eq!(
            public_key.eval(key, &tampered),
            public_key.eval(key, &ciphertext)
        );
        assert_eq!(secret_key.decrypt(&tampered), Ok(message));
    }

    pub(crate) fn shift_randomness(
        public_key: &PublicKey<Field128>,
        mut ciphertext: Ciphertext<Field128>,
    ) -> Ciphertext<Field128> {
        let params = &public_key.params;
        ciphertext.randomness = params.group().compose(
            &ciphertext.randomness,
            &params.power_of_generator(&IBig::ONE),
        );
        ciphertext
    }

    #[test]
    fn eval_rejects_inconsistent_randomness() {
        let (public_key, secret_key) = keys(3);
        let ciphertext = public_key.encrypt(&message(3), &mut rng()).unwrap();
        let ciphertext = shift_randomness(&public_key, ciphertext);
        let vector = message(3);
        let key = &secret_key.function_keys(&[vector.as_slice()]).unwrap()[0];
        assert_eq!(
            public_key.eval(key, &ciphertext),
            Err(CltError::NotInSubgroup)
        );
        assert_eq!(
            secret_key.decrypt(&ciphertext),
            Err(CltError::NotInSubgroup)
        );
    }

    #[test]
    fn master_secret_key_debug_is_redacted() {
        let (_, secret_key) = keys(16);
        assert_eq!(
            format!("{secret_key:?}"),
            "MasterSecretKey { dimension: 16, .. }"
        );
    }
}
