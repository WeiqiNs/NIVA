use niva::clt::{DISCRIMINANT_BITS, Params};
use niva::pear::{Analyst, Client, Server};
use niva::{Field128, PearError};
use rand::rngs::OsRng;
use rust_flpcp::Range;
use std::sync::Arc;

fn main() -> Result<(), PearError> {
    let rng = &mut OsRng;
    let params = Arc::new(Params::<Field128>::generate(DISCRIMINANT_BITS, rng)?);
    let circuit = Range::binary(4);
    let setup = Analyst::setup(&params, circuit.clone(), 4, rng)?;
    let client = Client::new(circuit.clone(), setup.public_key.clone())?;
    let server = Server::new(circuit, setup.public_key, setup.verification_key)?;

    let mut contributions = Vec::new();
    for input in [[1u64, 0, 1, 1], [0, 1, 1, 0], [2, 0, 0, 1]] {
        let ciphertext = client.encrypt(&input.map(Field128::from), rng)?;
        contributions.extend(server.validate(ciphertext));
    }
    assert_eq!(contributions.len(), 2);

    let aggregate = server.aggregate(&contributions, rng);
    let sum = setup.analyst.decrypt(&aggregate)?;
    assert_eq!(sum, [1u64, 1, 2, 1].map(Field128::from));
    Ok(())
}
