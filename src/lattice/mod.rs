mod params;
mod ring;

pub use params::{Headroom150, Headroom150Config, LatticeField, Params};

use crate::error::LatticeError;
use crate::error::PearError;
use crate::ipfe::{Ipfe, IpfePublicKey, redacted};
use crate::linear_algebra::linearly_independent;
use crate::sampling::centered_binomial;
use ark_std::cfg_iter;
use ark_std::rand::{CryptoRng, RngCore};
use params::{Polynomial, Residue};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::fmt;
use std::sync::Arc;

pub const MAX_DIMENSION: usize = 8192;

#[derive(Clone, Debug)]
pub struct PublicKey<F: LatticeField> {
    params: Arc<Params<F>>,
    mask: Polynomial<F>,
    bases: Vec<Polynomial<F>>,
}

pub struct MasterSecretKey<F: LatticeField> {
    params: Arc<Params<F>>,
    secrets: Vec<Polynomial<F>>,
}

pub struct DecryptionKey<F: LatticeField> {
    params: Arc<Params<F>>,
    secrets: Vec<Polynomial<F>>,
}

#[derive(Clone)]
pub struct FunctionKey<F: LatticeField> {
    coeffs: Vec<Residue<F>>,
    secret: Polynomial<F>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext<F: LatticeField> {
    randomness: Polynomial<F>,
    coords: Vec<Residue<F>>,
}

fn check_dimension(expected: usize, actual: usize) -> Result<(), LatticeError> {
    if expected != actual {
        return Err(LatticeError::DimensionMismatch { expected, actual });
    }
    Ok(())
}

fn check_prefix(len: usize, dimension: usize) -> Result<(), LatticeError> {
    if len > dimension {
        return Err(LatticeError::PrefixTooLong { len, dimension });
    }
    Ok(())
}

pub fn setup<F: LatticeField>(
    params: &Arc<Params<F>>,
    dimension: usize,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(PublicKey<F>, MasterSecretKey<F>), LatticeError> {
    if dimension > MAX_DIMENSION {
        return Err(LatticeError::DimensionTooLarge {
            dimension,
            maximum: MAX_DIMENSION,
        });
    }
    let mask = params.sample_uniform(rng);
    let coefficients: Vec<[Vec<i64>; 2]> = (0..dimension)
        .map(|_| {
            [
                params.sample_coefficients(rng),
                params.sample_coefficients(rng),
            ]
        })
        .collect();
    let (secrets, bases) = cfg_iter!(coefficients)
        .map(|[secret, error]| {
            let secret = params.forward(secret);
            let base = &(&mask * &secret) + &params.forward(error);
            (secret, base)
        })
        .unzip();
    Ok((
        PublicKey {
            params: Arc::clone(params),
            mask,
            bases,
        },
        MasterSecretKey {
            params: Arc::clone(params),
            secrets,
        },
    ))
}

impl<F: LatticeField> PublicKey<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.bases.len()
    }

    pub fn encrypt(
        &self,
        message: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Ciphertext<F>, LatticeError> {
        check_dimension(self.dimension(), message.len())?;
        Ok(self.encrypt_unchecked(message, rng))
    }

    fn encrypt_unchecked(
        &self,
        message: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Ciphertext<F> {
        let params = &self.params;
        let randomness = params.forward(&params.sample_coefficients(rng));
        let offset = params.forward(&params.sample_coefficients(rng));
        let noises: Vec<i64> = message.iter().map(|_| centered_binomial(rng)).collect();
        let coords = cfg_iter!(message)
            .zip(&self.bases)
            .zip(noises)
            .map(|((&value, base), noise)| {
                params.constant_term(base, &randomness)
                    + Residue::small(noise)
                    + params.encode(value)
            })
            .collect();
        Ciphertext {
            randomness: &(&self.mask * &randomness) + &offset,
            coords,
        }
    }

    pub fn eval(
        &self,
        key: &FunctionKey<F>,
        ciphertext: &Ciphertext<F>,
    ) -> Result<F, LatticeError> {
        check_dimension(key.coeffs.len(), ciphertext.dimension())?;
        self.params.decode(self.eval_raw(key, ciphertext))
    }

    fn eval_raw(&self, key: &FunctionKey<F>, ciphertext: &Ciphertext<F>) -> Residue<F> {
        let masked: Residue<F> = key
            .coeffs
            .iter()
            .zip(&ciphertext.coords)
            .map(|(&coeff, &coord)| coeff * coord)
            .sum();
        masked
            - self
                .params
                .constant_term(&ciphertext.randomness, &key.secret)
    }

    pub fn add(
        &self,
        left: &Ciphertext<F>,
        right: &Ciphertext<F>,
    ) -> Result<Ciphertext<F>, LatticeError> {
        check_dimension(left.dimension(), right.dimension())?;
        Ok(Self::add_unchecked(left, right))
    }

    fn add_unchecked(left: &Ciphertext<F>, right: &Ciphertext<F>) -> Ciphertext<F> {
        Ciphertext {
            randomness: &left.randomness + &right.randomness,
            coords: left
                .coords
                .iter()
                .zip(&right.coords)
                .map(|(&left, &right)| left + right)
                .collect(),
        }
    }

    pub fn prefix(&self, len: usize) -> Result<Self, LatticeError> {
        check_prefix(len, self.dimension())?;
        Ok(Self {
            params: Arc::clone(&self.params),
            mask: self.mask.clone(),
            bases: self.bases[..len].to_vec(),
        })
    }
}

impl<F: LatticeField> MasterSecretKey<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.secrets.len()
    }

    pub fn function_keys(
        self,
        vectors: &[&[F]],
    ) -> Result<(Vec<FunctionKey<F>>, DecryptionKey<F>), LatticeError> {
        for vector in vectors {
            check_dimension(self.dimension(), vector.len())?;
        }
        if !linearly_independent(vectors) {
            return Err(LatticeError::DependentFunctionVectors);
        }
        let keys = cfg_iter!(vectors)
            .map(|vector| {
                let coeffs: Vec<Residue<F>> =
                    vector.iter().map(|&value| Residue::lift(value)).collect();
                let secret = self.params.linear_combination(&coeffs, &self.secrets);
                FunctionKey { coeffs, secret }
            })
            .collect();
        let decryption_key = DecryptionKey {
            params: self.params,
            secrets: self.secrets,
        };
        Ok((keys, decryption_key))
    }
}

impl<F: LatticeField> DecryptionKey<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.secrets.len()
    }

    pub fn decrypt(&self, ciphertext: &Ciphertext<F>) -> Result<Vec<F>, LatticeError> {
        check_dimension(self.dimension(), ciphertext.dimension())?;
        let params = &self.params;
        cfg_iter!(ciphertext.coords)
            .zip(&self.secrets)
            .map(|(&coord, secret)| {
                params.decode(coord - params.constant_term(&ciphertext.randomness, secret))
            })
            .collect()
    }

    pub fn prefix(&self, len: usize) -> Result<Self, LatticeError> {
        check_prefix(len, self.dimension())?;
        Ok(Self {
            params: Arc::clone(&self.params),
            secrets: self.secrets[..len].to_vec(),
        })
    }
}

impl<F: LatticeField> fmt::Debug for MasterSecretKey<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "MasterSecretKey", self.secrets.len())
    }
}

impl<F: LatticeField> fmt::Debug for DecryptionKey<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "DecryptionKey", self.secrets.len())
    }
}

impl<F: LatticeField> FunctionKey<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.coeffs.len()
    }
}

impl<F: LatticeField> fmt::Debug for FunctionKey<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "FunctionKey", self.coeffs.len())
    }
}

impl<F: LatticeField> Ciphertext<F> {
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.coords.len()
    }

    pub fn prefix(mut self, len: usize) -> Result<Self, LatticeError> {
        check_prefix(len, self.dimension())?;
        self.coords.truncate(len);
        Ok(self)
    }
}

impl<F: LatticeField> IpfePublicKey<F> for PublicKey<F> {
    type Scheme = Params<F>;
}

impl<F: LatticeField> Ipfe<F> for Params<F> {
    type PublicKey = PublicKey<F>;
    type MasterSecretKey = MasterSecretKey<F>;
    type DecryptionKey = DecryptionKey<F>;
    type FunctionKey = FunctionKey<F>;
    type Ciphertext = Ciphertext<F>;

    fn setup(
        params: &Arc<Self>,
        dimension: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(PublicKey<F>, MasterSecretKey<F>), PearError> {
        Ok(setup(params, dimension, rng)?)
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
    ) -> Result<(Vec<FunctionKey<F>>, DecryptionKey<F>), PearError> {
        Ok(secret_key.function_keys(vectors)?)
    }

    fn encrypt(
        public_key: &PublicKey<F>,
        message: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Ciphertext<F> {
        public_key.encrypt_unchecked(message, rng)
    }

    fn eval(
        public_key: &PublicKey<F>,
        key: &FunctionKey<F>,
        ciphertext: &Ciphertext<F>,
    ) -> Result<F, PearError> {
        Ok(public_key.eval(key, ciphertext)?)
    }

    fn add(_: &PublicKey<F>, left: &Ciphertext<F>, right: &Ciphertext<F>) -> Ciphertext<F> {
        PublicKey::add_unchecked(left, right)
    }

    fn decrypt(
        decryption_key: &DecryptionKey<F>,
        ciphertext: &Ciphertext<F>,
    ) -> Result<Vec<F>, PearError> {
        Ok(decryption_key.decrypt(ciphertext)?)
    }

    fn prefix_public_key(public_key: &PublicKey<F>, len: usize) -> Result<PublicKey<F>, PearError> {
        Ok(public_key.prefix(len)?)
    }

    fn prefix_decryption_key(
        decryption_key: &DecryptionKey<F>,
        len: usize,
    ) -> Result<DecryptionKey<F>, PearError> {
        Ok(decryption_key.prefix(len)?)
    }

    fn truncate(ciphertext: Ciphertext<F>, len: usize) -> Result<Ciphertext<F>, PearError> {
        Ok(ciphertext.prefix(len)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) use super::params::tests::test_params;
    use super::params::tests::{TEST_RING_DIMENSION, integer, rng};
    use super::{Ciphertext, MasterSecretKey, PublicKey, Residue, setup};
    use crate::Field128;
    use crate::error::LatticeError;
    use crate::lattice::Headroom150;
    use crate::sampling::NOISE_ETA;
    use ark_ff::{AdditiveGroup, Field, PrimeField, UniformRand};
    use dashu_int::UBig;
    use std::sync::Arc;

    fn keys(dimension: usize) -> (PublicKey<Field128>, MasterSecretKey<Field128>) {
        setup(&Arc::new(test_params()), dimension, &mut rng()).unwrap()
    }

    fn random(len: usize, rng: &mut impl ark_std::rand::Rng) -> Vec<Field128> {
        (0..len).map(|_| Field128::rand(rng)).collect()
    }

    fn inner_product(x: &[Field128], y: &[Field128]) -> Field128 {
        x.iter().zip(y).map(|(a, b)| *a * b).sum()
    }

    fn is_negative<K: PrimeField>(value: K) -> bool {
        value.into_bigint() > K::MODULUS_MINUS_ONE_DIV_TWO
    }

    pub(crate) fn magnitude<K: PrimeField>(value: K) -> UBig {
        integer(&if is_negative(value) { -value } else { value }.into_bigint())
    }

    fn centred<K: PrimeField>(value: K) -> f64 {
        let magnitude = magnitude(value).to_f64().value();
        if is_negative(value) {
            -magnitude
        } else {
            magnitude
        }
    }

    pub(crate) fn push_past_ceiling(
        mut ciphertext: Ciphertext<Field128>,
        index: usize,
        coefficient: Field128,
    ) -> Ciphertext<Field128> {
        let delta = integer(&Headroom150::MODULUS);
        let denominator = magnitude(coefficient) << 3;
        let shift = (UBig::from(3u8) * delta + &denominator - UBig::ONE) / &denominator;
        let bytes = shift.to_le_bytes();
        ciphertext.coords[index] = ciphertext.coords[index]
            + Residue {
                field: Field128::from_le_bytes_mod_order(&bytes),
                headroom: Headroom150::from_le_bytes_mod_order(&bytes),
            };
        ciphertext
    }

    #[test]
    fn noise_matches_its_predicted_spread() {
        const DIMENSION: usize = 16;
        const ENCRYPTIONS: u16 = 256;
        let mut rng = rng();
        let (public_key, secret_key) = keys(DIMENSION);
        let mut unit = vec![Field128::ZERO; DIMENSION];
        unit[0] = Field128::ONE;
        let vectors = [
            random(DIMENSION, &mut rng),
            random(DIMENSION, &mut rng),
            unit,
        ];
        let slices: Vec<&[Field128]> = vectors.iter().map(Vec::as_slice).collect();
        let (keys, decryption_key) = secret_key.function_keys(&slices).unwrap();

        let messages: Vec<Vec<Field128>> = (0..ENCRYPTIONS)
            .map(|_| random(DIMENSION, &mut rng))
            .collect();
        let ciphertexts: Vec<Ciphertext<Field128>> = messages
            .iter()
            .map(|message| public_key.encrypt(message, &mut rng).unwrap())
            .collect();
        for (ciphertext, message) in ciphertexts.iter().zip(&messages) {
            assert_eq!(decryption_key.decrypt(ciphertext).as_ref(), Ok(message));
        }

        let variance = f64::from(NOISE_ETA) / 2.0;
        let ring_dimension = f64::from(u32::try_from(TEST_RING_DIMENSION).unwrap());
        let per_unit_coefficient = 2.0 * ring_dimension * variance.powi(2) + variance;
        let delta = integer(&Headroom150::MODULUS).to_f64().value();
        let count = f64::from(ENCRYPTIONS);
        for (key, vector) in keys.iter().zip(&vectors) {
            let squared_norm: f64 = vector.iter().map(|&y| centred(y).powi(2)).sum();
            let predicted = (squared_norm * per_unit_coefficient).sqrt();
            let noises: Vec<f64> = ciphertexts
                .iter()
                .zip(&messages)
                .map(|(ciphertext, message)| {
                    assert_eq!(
                        public_key.eval(key, ciphertext),
                        Ok(inner_product(message, vector))
                    );
                    centred(public_key.eval_raw(key, ciphertext).headroom)
                })
                .collect();
            let mean = noises.iter().sum::<f64>() / count;
            let deviation =
                (noises.iter().map(|e| (e - mean).powi(2)).sum::<f64>() / (count - 1.0)).sqrt();
            let ratio = deviation / predicted;
            assert!((0.85..=1.15).contains(&ratio), "{ratio}");
            assert!(noises.iter().any(|&e| e < 0.0));
            assert!(noises.iter().any(|&e| e > 0.0));
            assert!(noises.iter().all(|e| e.abs() < delta / 16.0));
        }
    }

    #[test]
    fn eval_rejects_noise_above_the_ceiling() {
        let mut rng = rng();
        let (public_key, secret_key) = keys(4);
        let mut vector = random(4, &mut rng);
        vector[0] = Field128::from(1u64 << 20);
        let message = random(4, &mut rng);
        let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();
        let (keys, decryption_key) = secret_key.function_keys(&[vector.as_slice()]).unwrap();
        assert_eq!(
            public_key.eval(&keys[0], &ciphertext),
            Ok(inner_product(&message, &vector))
        );

        let shifted = push_past_ceiling(ciphertext, 0, vector[0]);
        assert_eq!(
            public_key.eval(&keys[0], &shifted),
            Err(LatticeError::NoiseTooLarge)
        );
        assert_eq!(decryption_key.decrypt(&shifted), Ok(message));
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let (_, secret_key) = keys(16);
        assert_eq!(
            format!("{secret_key:?}"),
            "MasterSecretKey { dimension: 16, .. }"
        );
        let vector = random(16, &mut rng());
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
