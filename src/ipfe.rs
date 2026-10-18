use ark_ff::PrimeField;
use ark_std::rand::{CryptoRng, RngCore};
use std::fmt::Debug;
use std::sync::Arc;

pub type FunctionKeys<F, S> = (
    Vec<<S as Ipfe<F>>::FunctionKey>,
    <S as Ipfe<F>>::DecryptionKey,
);

pub trait Ipfe<F: PrimeField>: Debug {
    type Error: std::error::Error;
    type PublicKey: Clone + Debug + Sync;
    type MasterSecretKey;
    type DecryptionKey: Debug;
    type FunctionKey: Clone + Sync;
    type Ciphertext: Clone + Send + Sync;

    fn setup(
        scheme: &Arc<Self>,
        dimension: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(Self::PublicKey, Self::MasterSecretKey), Self::Error>;

    fn dimension(public_key: &Self::PublicKey) -> usize;

    fn key_dimension(key: &Self::FunctionKey) -> usize;

    fn function_keys(
        secret_key: Self::MasterSecretKey,
        vectors: &[&[F]],
    ) -> Result<FunctionKeys<F, Self>, Self::Error>;

    fn encrypt(
        public_key: &Self::PublicKey,
        message: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Self::Ciphertext, Self::Error>;

    fn eval(
        public_key: &Self::PublicKey,
        key: &Self::FunctionKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<F, Self::Error>;

    fn add(
        public_key: &Self::PublicKey,
        left: &Self::Ciphertext,
        right: &Self::Ciphertext,
    ) -> Result<Self::Ciphertext, Self::Error>;

    fn decrypt(
        decryption_key: &Self::DecryptionKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Vec<F>, Self::Error>;

    fn prefix_public_key(
        public_key: &Self::PublicKey,
        len: usize,
    ) -> Result<Self::PublicKey, Self::Error>;

    fn prefix_decryption_key(
        decryption_key: &Self::DecryptionKey,
        len: usize,
    ) -> Result<Self::DecryptionKey, Self::Error>;

    fn prefix_ciphertext(
        ciphertext: Self::Ciphertext,
        len: usize,
    ) -> Result<Self::Ciphertext, Self::Error>;
}
