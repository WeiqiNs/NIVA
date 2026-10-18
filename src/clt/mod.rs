mod params;

pub use params::Params;

use crate::class_group::{FixedBase, Form, multi_exp, pow};
use crate::debug::redacted;
use crate::error::CltError;
use crate::ipfe::{Ipfe, IpfePublicKey};
use crate::linear_algebra::linearly_independent;
use ark_ff::PrimeField;
use ark_std::cfg_iter;
use ark_std::rand::{CryptoRng, RngCore};
use dashu_int::IBig;
use dashu_int::ops::BitTest;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
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

pub struct DecryptionKey<F> {
    params: Arc<Params<F>>,
    exponents: Vec<IBig>,
}

#[derive(Clone)]
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

pub fn setup<F: PrimeField>(
    params: &Arc<Params<F>>,
    dimension: usize,
    rng: &mut (impl CryptoRng + RngCore),
) -> (PublicKey<F>, MasterSecretKey<F>) {
    let exponents: Vec<IBig> = (0..dimension).map(|_| params.sample_key(rng)).collect();
    let bases = cfg_iter!(exponents)
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

    fn encrypt_unchecked(
        &self,
        message: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Ciphertext<F> {
        let params = &self.params;
        let group = params.group();
        let randomness = params.sample_randomness(rng);
        let coords = cfg_iter!(message)
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
        let masked = multi_exp(group, &ciphertext.coords, &key.coeffs);
        let mask = pow(group, &ciphertext.randomness, &-&key.secret);
        self.params.decode(&group.compose(&masked, &mask))
    }

    pub fn add(
        &self,
        left: &Ciphertext<F>,
        right: &Ciphertext<F>,
    ) -> Result<Ciphertext<F>, CltError> {
        check_dimension(left.dimension(), right.dimension())?;
        let group = self.params.group();
        Ok(Ciphertext {
            randomness: group.compose(&left.randomness, &right.randomness),
            coords: left
                .coords
                .iter()
                .zip(&right.coords)
                .map(|(left, right)| group.compose(left, right))
                .collect(),
            _field: PhantomData,
        })
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

    pub fn function_keys(
        self,
        vectors: &[&[F]],
    ) -> Result<(Vec<FunctionKey<F>>, DecryptionKey<F>), CltError> {
        for vector in vectors {
            check_dimension(self.dimension(), vector.len())?;
        }
        if !linearly_independent(vectors) {
            return Err(CltError::DependentFunctionVectors);
        }
        let keys = vectors
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
            .collect();
        let decryption_key = DecryptionKey {
            params: self.params,
            exponents: self.exponents,
        };
        Ok((keys, decryption_key))
    }
}

impl<F: PrimeField> DecryptionKey<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.exponents.len()
    }

    pub fn decrypt(&self, ciphertext: &Ciphertext<F>) -> Result<Vec<F>, CltError> {
        check_dimension(self.dimension(), ciphertext.dimension())?;
        let group = self.params.group();
        let max_bits = self
            .exponents
            .iter()
            .map(BitTest::bit_len)
            .max()
            .unwrap_or(0);
        let unmask = FixedBase::new(group, ciphertext.randomness.inverse(), max_bits);
        cfg_iter!(ciphertext.coords)
            .zip(&self.exponents)
            .map(|(coord, exponent)| {
                let mask = unmask.pow(group, exponent);
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
        redacted(f, "MasterSecretKey", self.exponents.len())
    }
}

impl<F> fmt::Debug for DecryptionKey<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "DecryptionKey", self.exponents.len())
    }
}

impl<F> FunctionKey<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.coeffs.len()
    }
}

impl<F> fmt::Debug for FunctionKey<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "FunctionKey", self.coeffs.len())
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

impl<F: PrimeField> IpfePublicKey<F> for PublicKey<F> {
    type Scheme = Params<F>;
}

impl<F: PrimeField> Ipfe<F> for Params<F> {
    type Error = CltError;
    type PublicKey = PublicKey<F>;
    type MasterSecretKey = MasterSecretKey<F>;
    type DecryptionKey = DecryptionKey<F>;
    type FunctionKey = FunctionKey<F>;
    type Ciphertext = Ciphertext<F>;

    fn setup(
        params: &Arc<Self>,
        dimension: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(PublicKey<F>, MasterSecretKey<F>), CltError> {
        Ok(setup(params, dimension, rng))
    }

    fn dimension(public_key: &PublicKey<F>) -> usize {
        public_key.dimension()
    }

    fn key_dimension(key: &FunctionKey<F>) -> usize {
        key.dimension()
    }

    fn function_keys(
        secret_key: MasterSecretKey<F>,
        vectors: &[&[F]],
    ) -> Result<(Vec<FunctionKey<F>>, DecryptionKey<F>), CltError> {
        secret_key.function_keys(vectors)
    }

    fn encrypt(
        public_key: &PublicKey<F>,
        message: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Ciphertext<F>, CltError> {
        public_key.encrypt(message, rng)
    }

    fn encrypt_zeros(
        public_key: &PublicKey<F>,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Ciphertext<F> {
        public_key.encrypt_unchecked(&vec![F::ZERO; public_key.dimension()], rng)
    }

    fn eval(
        public_key: &PublicKey<F>,
        key: &FunctionKey<F>,
        ciphertext: &Ciphertext<F>,
    ) -> Result<F, CltError> {
        public_key.eval(key, ciphertext)
    }

    fn add(
        public_key: &PublicKey<F>,
        left: &Ciphertext<F>,
        right: &Ciphertext<F>,
    ) -> Result<Ciphertext<F>, CltError> {
        public_key.add(left, right)
    }

    fn decrypt(
        decryption_key: &DecryptionKey<F>,
        ciphertext: &Ciphertext<F>,
    ) -> Result<Vec<F>, CltError> {
        decryption_key.decrypt(ciphertext)
    }

    fn prefix_public_key(public_key: &PublicKey<F>, len: usize) -> Result<PublicKey<F>, CltError> {
        public_key.prefix(len)
    }

    fn prefix_decryption_key(
        decryption_key: &DecryptionKey<F>,
        len: usize,
    ) -> Result<DecryptionKey<F>, CltError> {
        decryption_key.prefix(len)
    }

    fn truncate(ciphertext: Ciphertext<F>, len: usize) -> Result<Ciphertext<F>, CltError> {
        ciphertext.prefix(len)
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
        let (_, decryption_key) = secret_key.function_keys(&[]).unwrap();
        assert_eq!(decryption_key.decrypt(&ciphertext), Ok(message));
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

        let (keys, decryption_key) = secret_key.function_keys(&[message.as_slice()]).unwrap();
        assert_eq!(
            public_key.eval(&keys[0], &tampered),
            public_key.eval(&keys[0], &ciphertext)
        );
        assert_eq!(decryption_key.decrypt(&tampered), Ok(message));
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
        let (keys, decryption_key) = secret_key.function_keys(&[vector.as_slice()]).unwrap();
        assert_eq!(
            public_key.eval(&keys[0], &ciphertext),
            Err(CltError::NotInSubgroup)
        );
        assert_eq!(
            decryption_key.decrypt(&ciphertext),
            Err(CltError::NotInSubgroup)
        );
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let (_, secret_key) = keys(16);
        assert_eq!(
            format!("{secret_key:?}"),
            "MasterSecretKey { dimension: 16, .. }"
        );
        let vector = message(16);
        let (keys, decryption_key) = secret_key.function_keys(&[vector.as_slice()]).unwrap();
        assert_eq!(
            format!("{decryption_key:?}"),
            "DecryptionKey { dimension: 16, .. }"
        );
        assert_eq!(
            format!("{:?}", keys[0]),
            "FunctionKey { dimension: 16, .. }"
        );
    }
}
