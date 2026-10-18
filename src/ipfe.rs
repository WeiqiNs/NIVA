use crate::error::PearError;
use ark_ff::PrimeField;
use ark_std::rand::{CryptoRng, RngCore};
use std::fmt::{self, Debug};
use std::sync::Arc;

pub trait Ipfe<F: PrimeField>: Debug {
    type PublicKey: Clone + Sync + IpfePublicKey<F, Scheme = Self>;
    type MasterSecretKey;
    type DecryptionKey: Debug;
    type FunctionKey: Clone + Sync;
    type Ciphertext: Clone + Send + Sync;

    fn setup(
        params: &Arc<Self>,
        dimension: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(Self::PublicKey, Self::MasterSecretKey), PearError>;

    fn dimension(public_key: &Self::PublicKey) -> usize;

    fn key_dimension(key: &Self::FunctionKey) -> usize;

    fn function_keys(
        secret_key: Self::MasterSecretKey,
        vectors: &[&[F]],
    ) -> Result<(Vec<Self::FunctionKey>, Self::DecryptionKey), PearError>;

    fn encrypt(
        public_key: &Self::PublicKey,
        message: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self::Ciphertext, PearError>;

    fn encrypt_zeros(
        public_key: &Self::PublicKey,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Self::Ciphertext;

    fn eval(
        public_key: &Self::PublicKey,
        key: &Self::FunctionKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<F, PearError>;

    fn add(
        public_key: &Self::PublicKey,
        left: &Self::Ciphertext,
        right: &Self::Ciphertext,
    ) -> Self::Ciphertext;

    fn decrypt(
        decryption_key: &Self::DecryptionKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Vec<F>, PearError>;

    fn prefix_public_key(
        public_key: &Self::PublicKey,
        len: usize,
    ) -> Result<Self::PublicKey, PearError>;

    fn prefix_decryption_key(
        decryption_key: &Self::DecryptionKey,
        len: usize,
    ) -> Result<Self::DecryptionKey, PearError>;

    fn truncate(ciphertext: Self::Ciphertext, len: usize) -> Result<Self::Ciphertext, PearError>;
}

pub trait IpfePublicKey<F: PrimeField> {
    type Scheme: Ipfe<F, PublicKey = Self>;
}

pub(crate) fn redacted(f: &mut fmt::Formatter<'_>, name: &str, dimension: usize) -> fmt::Result {
    f.debug_struct(name)
        .field("dimension", &dimension)
        .finish_non_exhaustive()
}
