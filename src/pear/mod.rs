use crate::clt::{self, Ciphertext, FunctionKey, MasterSecretKey, Params, PublicKey};
use crate::error::PearError;
use ark_ff::PrimeField;
use ark_std::rand::{CryptoRng, RngCore};
use rust_flpcp::{Circuit, Flp, Query};
use std::sync::Arc;

#[derive(Debug)]
pub struct Analyst<F> {
    secret: MasterSecretKey<F>,
}

#[derive(Debug)]
pub struct Setup<F> {
    pub analyst: Analyst<F>,
    pub public_key: PublicKey<F>,
    pub verification_key: VerificationKey<F>,
}

#[derive(Clone, Debug)]
pub struct VerificationKey<F> {
    query: Query<F>,
    function_keys: Vec<FunctionKey<F>>,
    payload_len: usize,
}

#[derive(Debug)]
pub struct Client<F: PrimeField, C> {
    flp: Flp<F, C>,
    public_key: PublicKey<F>,
}

#[derive(Debug)]
pub struct Server<F: PrimeField, C> {
    flp: Flp<F, C>,
    public_key: PublicKey<F>,
    payload_key: PublicKey<F>,
    verification_key: VerificationKey<F>,
}

#[derive(Clone, Debug)]
pub struct Contribution<F>(Ciphertext<F>);

impl<F: PrimeField> Analyst<F> {
    pub fn setup<C: Circuit<F>>(
        params: &Arc<Params<F>>,
        circuit: C,
        payload_len: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Setup<F>, PearError> {
        let input_len = circuit.input_len();
        if payload_len > input_len {
            return Err(PearError::PayloadTooLong {
                payload_len,
                input_len,
            });
        }
        let flp = Flp::new(circuit)?;
        let (public_key, secret_key) = clt::setup(params, flp.vector_len(), rng);
        let query = flp.query(rng);
        let vectors: Vec<&[F]> = query
            .linear_queries()
            .iter()
            .map(|linear| linear.coeffs.as_slice())
            .collect();
        let function_keys = secret_key.function_keys(&vectors)?;
        Ok(Setup {
            analyst: Self {
                secret: secret_key.prefix(payload_len)?,
            },
            public_key,
            verification_key: VerificationKey {
                query,
                function_keys,
                payload_len,
            },
        })
    }

    pub fn decrypt(&self, aggregate: &Ciphertext<F>) -> Result<Vec<F>, PearError> {
        Ok(self.secret.decrypt(aggregate)?)
    }
}

impl<F: PrimeField, C: Circuit<F>> Client<F, C> {
    pub fn new(circuit: C, public_key: PublicKey<F>) -> Result<Self, PearError> {
        let flp = Flp::new(circuit)?;
        if public_key.dimension() != flp.vector_len() {
            return Err(PearError::CircuitMismatch);
        }
        Ok(Self { flp, public_key })
    }

    pub fn encrypt(
        &self,
        input: &[F],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Ciphertext<F>, PearError> {
        let vector = self.flp.prove(input, rng)?;
        Ok(self.public_key.encrypt_unchecked(&vector, rng))
    }
}

impl<F: PrimeField, C: Circuit<F>> Server<F, C> {
    pub fn new(
        circuit: C,
        public_key: PublicKey<F>,
        verification_key: VerificationKey<F>,
    ) -> Result<Self, PearError> {
        let input_len = circuit.input_len();
        let flp = Flp::new(circuit)?;
        if public_key.dimension() != flp.vector_len()
            || verification_key.function_keys.len() != flp.query_count()
            || verification_key.payload_len > input_len
        {
            return Err(PearError::CircuitMismatch);
        }
        Ok(Self {
            flp,
            payload_key: public_key.prefix(verification_key.payload_len)?,
            public_key,
            verification_key,
        })
    }

    #[must_use]
    pub fn validate(&self, ciphertext: Ciphertext<F>) -> Option<Contribution<F>> {
        let VerificationKey {
            query,
            function_keys,
            payload_len,
        } = &self.verification_key;
        let answers = function_keys
            .iter()
            .zip(query.linear_queries())
            .map(|(key, linear)| {
                Some(self.public_key.eval(key, &ciphertext).ok()? + linear.constant)
            })
            .collect::<Option<Vec<F>>>()?;
        if !self.flp.decide(query, &answers) {
            return None;
        }
        ciphertext.prefix(*payload_len).ok().map(Contribution)
    }

    pub fn aggregate(
        &self,
        contributions: &[Contribution<F>],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Ciphertext<F> {
        let zeros = vec![F::ZERO; self.verification_key.payload_len];
        contributions.iter().fold(
            self.payload_key.encrypt_unchecked(&zeros, rng),
            |sum, Contribution(ciphertext)| self.payload_key.add_unchecked(&sum, ciphertext),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Analyst, Client, Server};
    use crate::Field128;
    use crate::clt::tests::{rng, shift_randomness, test_params};
    use ark_ff::{AdditiveGroup, Field};
    use rust_flpcp::Range;
    use std::sync::Arc;

    #[test]
    fn validate_rejects_inconsistent_randomness() {
        let mut rng = rng();
        let circuit = Range::binary(4);
        let setup = Analyst::setup(&Arc::new(test_params()), circuit.clone(), 4, &mut rng).unwrap();
        let client = Client::new(circuit.clone(), setup.public_key.clone()).unwrap();
        let server =
            Server::new(circuit, setup.public_key.clone(), setup.verification_key).unwrap();
        let input = [Field128::ONE, Field128::ZERO, Field128::ONE, Field128::ONE];
        let ciphertext = client.encrypt(&input, &mut rng).unwrap();
        assert!(server.validate(ciphertext.clone()).is_some());
        assert!(
            server
                .validate(shift_randomness(&setup.public_key, ciphertext))
                .is_none()
        );
    }
}
