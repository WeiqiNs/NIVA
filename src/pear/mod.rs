use crate::clt::Clt;
use crate::error::PearError;
use crate::ipfe::Ipfe;
use ark_ff::PrimeField;
use ark_std::cfg_iter;
use ark_std::rand::{CryptoRng, RngCore};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use rust_flpcp::{Circuit, Flp, Query};
use std::fmt;
use std::sync::Arc;

#[derive(Debug)]
pub struct Analyst<F: PrimeField, S: Ipfe<F> = Clt<F>> {
    secret: S::DecryptionKey,
}

#[derive(Debug)]
pub struct Setup<F: PrimeField, S: Ipfe<F> = Clt<F>> {
    pub analyst: Analyst<F, S>,
    pub public_key: PublicKey<F, S>,
    pub verification_key: VerificationKey<F, S>,
}

#[derive(Debug)]
pub struct PublicKey<F: PrimeField, S: Ipfe<F> = Clt<F>>(pub S::PublicKey);

pub struct VerificationKey<F: PrimeField, S: Ipfe<F> = Clt<F>> {
    query: Query<F>,
    function_keys: Vec<S::FunctionKey>,
    payload_len: usize,
}

#[derive(Debug)]
pub struct Client<F: PrimeField, C, S: Ipfe<F> = Clt<F>> {
    flp: Flp<F, C>,
    public_key: S::PublicKey,
}

#[derive(Debug)]
pub struct Server<F: PrimeField, C, S: Ipfe<F> = Clt<F>> {
    flp: Flp<F, C>,
    public_key: S::PublicKey,
    payload_key: S::PublicKey,
    verification_key: VerificationKey<F, S>,
}

#[derive(Debug)]
pub struct Contribution<F: PrimeField, S: Ipfe<F> = Clt<F>>(S::Ciphertext);

impl<F: PrimeField, S: Ipfe<F>> Clone for PublicKey<F, S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<F: PrimeField, S: Ipfe<F>> Clone for VerificationKey<F, S> {
    fn clone(&self) -> Self {
        Self {
            query: self.query.clone(),
            function_keys: self.function_keys.clone(),
            payload_len: self.payload_len,
        }
    }
}

impl<F: PrimeField, S: Ipfe<F>> fmt::Debug for VerificationKey<F, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationKey")
            .field("queries", &self.function_keys.len())
            .field("payload_len", &self.payload_len)
            .finish_non_exhaustive()
    }
}

impl<F: PrimeField, S: Ipfe<F>> Clone for Contribution<F, S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(feature = "parallel")]
fn tree_reduce<T: Send, E: Send>(
    items: Vec<T>,
    combine: impl Fn(T, T) -> Result<T, E> + Send + Sync,
) -> Result<Option<T>, E> {
    items
        .into_par_iter()
        .map(Ok)
        .try_reduce_with(combine)
        .transpose()
}

#[cfg(not(feature = "parallel"))]
fn tree_reduce<T, E>(
    items: Vec<T>,
    combine: impl Fn(T, T) -> Result<T, E>,
) -> Result<Option<T>, E> {
    let mut items = items.into_iter();
    items
        .next()
        .map(|first| items.try_fold(first, combine))
        .transpose()
}

impl<F: PrimeField, S: Ipfe<F>> Analyst<F, S>
where
    PearError: From<S::Error>,
{
    pub fn setup<C: Circuit<F>>(
        scheme: &Arc<S>,
        circuit: C,
        payload_len: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Setup<F, S>, PearError> {
        let input_len = circuit.input_len();
        if payload_len > input_len {
            return Err(PearError::PayloadTooLong {
                payload_len,
                input_len,
            });
        }
        let flp = Flp::new(circuit)?;
        let (public_key, secret_key) = S::setup(scheme, flp.vector_len(), rng)?;
        let query = flp.query(rng);
        let vectors: Vec<&[F]> = query
            .linear_queries()
            .iter()
            .map(|linear| linear.coeffs.as_slice())
            .collect();
        let (function_keys, decryption_key) = S::function_keys(secret_key, &vectors)?;
        Ok(Setup {
            analyst: Self {
                secret: S::prefix_decryption_key(&decryption_key, payload_len)?,
            },
            public_key: PublicKey(public_key),
            verification_key: VerificationKey {
                query,
                function_keys,
                payload_len,
            },
        })
    }

    pub fn decrypt(&self, aggregate: &S::Ciphertext) -> Result<Vec<F>, PearError> {
        Ok(S::decrypt(&self.secret, aggregate)?)
    }
}

impl<F: PrimeField, C: Circuit<F>, S: Ipfe<F>> Client<F, C, S>
where
    PearError: From<S::Error>,
{
    pub fn new(circuit: C, PublicKey(public_key): PublicKey<F, S>) -> Result<Self, PearError> {
        let flp = Flp::new(circuit)?;
        if S::dimension(&public_key) != flp.vector_len() {
            return Err(PearError::CircuitMismatch);
        }
        Ok(Self { flp, public_key })
    }

    pub fn encrypt(
        &self,
        input: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<S::Ciphertext, PearError> {
        let vector = self.flp.prove(input, rng)?;
        Ok(S::encrypt(&self.public_key, &vector, rng)?)
    }
}

impl<F: PrimeField, C: Circuit<F>, S: Ipfe<F>> Server<F, C, S>
where
    PearError: From<S::Error>,
{
    pub fn new(
        circuit: C,
        PublicKey(public_key): PublicKey<F, S>,
        verification_key: VerificationKey<F, S>,
    ) -> Result<Self, PearError> {
        let input_len = circuit.input_len();
        let flp = Flp::new(circuit)?;
        if S::dimension(&public_key) != flp.vector_len()
            || verification_key.function_keys.len() != flp.query_count()
            || verification_key
                .function_keys
                .iter()
                .any(|key| S::key_dimension(key) != flp.vector_len())
            || verification_key.payload_len > input_len
        {
            return Err(PearError::CircuitMismatch);
        }
        Ok(Self {
            flp,
            payload_key: S::prefix_public_key(&public_key, verification_key.payload_len)?,
            public_key,
            verification_key,
        })
    }

    #[must_use]
    pub fn validate(&self, ciphertext: S::Ciphertext) -> Option<Contribution<F, S>> {
        let VerificationKey {
            query,
            function_keys,
            payload_len,
        } = &self.verification_key;
        let public_key = &self.public_key;
        let answers = cfg_iter!(function_keys)
            .zip(query.linear_queries())
            .map(|(key, linear)| {
                Some(S::eval(public_key, key, &ciphertext).ok()? + linear.constant)
            })
            .collect::<Option<Vec<F>>>()?;
        if !self.flp.decide(query, &answers) {
            return None;
        }
        S::truncate(ciphertext, *payload_len).ok().map(Contribution)
    }

    pub fn aggregate(
        &self,
        contributions: &[Contribution<F, S>],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<S::Ciphertext, PearError> {
        let payload_key = &self.payload_key;
        let fresh = S::encrypt(payload_key, &vec![F::ZERO; S::dimension(payload_key)], rng)?;
        let ciphertexts = contributions
            .iter()
            .map(|Contribution(ciphertext)| ciphertext.clone())
            .collect();
        let sum = tree_reduce(ciphertexts, |left, right| {
            S::add(payload_key, &left, &right).map_err(PearError::from)
        })?;
        Ok(match sum {
            Some(sum) => S::add(payload_key, &fresh, &sum)?,
            None => fresh,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Analyst, Client, Server};
    use crate::Field128;
    use crate::clt::tests::{rng, shift_randomness, test_scheme};
    use crate::lattice::tests::{magnitude, push_past_ceiling};
    use ark_ff::{AdditiveGroup, Field};
    use rust_flpcp::Range;
    use std::sync::Arc;

    #[test]
    fn validate_rejects_inconsistent_randomness() {
        let mut rng = rng();
        let circuit = Range::binary(4);
        let setup = Analyst::setup(&Arc::new(test_scheme()), circuit.clone(), 4, &mut rng).unwrap();
        let client = Client::new(circuit.clone(), setup.public_key.clone()).unwrap();
        let server =
            Server::new(circuit, setup.public_key.clone(), setup.verification_key).unwrap();
        let input = [Field128::ONE, Field128::ZERO, Field128::ONE, Field128::ONE];
        let ciphertext = client.encrypt(&input, &mut rng).unwrap();
        assert!(server.validate(ciphertext.clone()).is_some());
        assert!(
            server
                .validate(shift_randomness(&setup.public_key.0, ciphertext))
                .is_none()
        );
    }

    #[test]
    fn validate_rejects_noise_above_the_ceiling() {
        let mut rng = rng();
        let circuit = Range::binary(4);
        let scheme = Arc::new(crate::lattice::tests::test_scheme());
        let setup = Analyst::setup(&scheme, circuit.clone(), 4, &mut rng).unwrap();
        let client = Client::new(circuit.clone(), setup.public_key.clone()).unwrap();
        let server = Server::new(
            circuit.clone(),
            setup.public_key,
            setup.verification_key.clone(),
        )
        .unwrap();
        let input = [Field128::ONE, Field128::ZERO, Field128::ONE, Field128::ONE];
        let ciphertext = client.encrypt(&input, &mut rng).unwrap();
        assert!(server.validate(ciphertext.clone()).is_some());

        let coeffs = &setup.verification_key.query.linear_queries()[0].coeffs;
        let index = (0..input.len())
            .max_by_key(|&index| magnitude(coeffs[index]))
            .unwrap();
        let shifted = push_past_ceiling(ciphertext, index, coeffs[index]);
        assert!(server.validate(shifted.clone()).is_none());
        assert_eq!(
            setup.analyst.decrypt(&shifted.prefix(4).unwrap()),
            Ok(input.to_vec())
        );
    }
}
