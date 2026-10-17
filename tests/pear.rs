mod common;

use ark_ff::{AdditiveGroup, Field};
use common::{TEST_DISCRIMINANT_BITS, params, rng};
use niva::clt::{Ciphertext, Params, PublicKey};
use niva::pear::{Analyst, Client, Contribution, Server, Setup};
use niva::{CltError, Field128, PearError};
use rust_flpcp::{Circuit, Flp, FlpError, MeanVariance, NormBound, Range};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;

struct Case<C> {
    circuit: C,
    payload_len: usize,
    honest: Vec<Vec<Field128>>,
    invalid: Vec<Field128>,
}

fn values(values: &[u64]) -> Vec<Field128> {
    values.iter().map(|&value| Field128::from(value)).collect()
}

fn shape<C: Circuit<Field128>>(circuit: C) -> (usize, usize) {
    let flp = Flp::<Field128, C>::new(circuit).unwrap();
    (flp.vector_len(), flp.query_count())
}

fn roles<C: Circuit<Field128> + Clone>(
    circuit: &C,
    payload_len: usize,
) -> (Setup<Field128>, Client<Field128, C>, Server<Field128, C>) {
    let setup = Analyst::setup(&params(), circuit.clone(), payload_len, &mut rng()).unwrap();
    let client = Client::new(circuit.clone(), setup.public_key.clone()).unwrap();
    let server = Server::new(
        circuit.clone(),
        setup.public_key.clone(),
        setup.verification_key.clone(),
    )
    .unwrap();
    (setup, client, server)
}

fn assert_protocol<C: Circuit<Field128> + Clone + Debug>(case: &Case<C>) {
    let mut rng = rng();
    let label = format!("{:?}", case.circuit);
    let (setup, client, server) = roles(&case.circuit, case.payload_len);

    let contributions: Vec<Contribution<Field128>> = case
        .honest
        .iter()
        .map(|input| {
            let ciphertext = client.encrypt(input, &mut rng).unwrap();
            server.validate(ciphertext).expect(&label)
        })
        .collect();
    let invalid = client.encrypt(&case.invalid, &mut rng).unwrap();
    assert!(server.validate(invalid).is_none(), "{label}");

    let flp = Flp::new(case.circuit.clone()).unwrap();
    let vector = flp.prove(&case.honest[0], &mut rng).unwrap();
    let public_key = &setup.public_key;
    let untampered = public_key.encrypt(&vector, &mut rng).unwrap();
    assert!(server.validate(untampered).is_some(), "{label}");
    let input_len = case.circuit.input_len();
    for position in [0, input_len, input_len + 1, flp.vector_len() - 1] {
        let mut tampered = vector.clone();
        tampered[position] += Field128::ONE;
        let ciphertext = public_key.encrypt(&tampered, &mut rng).unwrap();
        assert!(server.validate(ciphertext).is_none(), "{label} {position}");
    }

    let mut expected = vec![Field128::ZERO; case.payload_len];
    for input in &case.honest {
        for (sum, value) in expected.iter_mut().zip(input) {
            *sum += value;
        }
    }
    let aggregate = server.aggregate(&contributions, &mut rng);
    assert_eq!(setup.analyst.decrypt(&aggregate), Ok(expected), "{label}");
}

#[test]
fn honest_clients_aggregate_and_invalid_clients_are_rejected() {
    assert_protocol(&Case {
        circuit: Range::binary(4),
        payload_len: 4,
        honest: vec![
            values(&[1, 0, 1, 1]),
            values(&[0, 1, 1, 0]),
            values(&[1, 1, 1, 1]),
        ],
        invalid: values(&[2, 0, 0, 1]),
    });

    let norm_bound = NormBound {
        len: 3,
        input_bits: 3,
        norm_bits: 6,
        square_chunk: None,
    };
    assert_protocol(&Case {
        honest: [[1, 2, 3], [7, 0, 0], [3, 3, 3]]
            .iter()
            .map(|values| norm_bound.encode(values))
            .collect(),
        invalid: norm_bound.encode(&[7, 7, 7]),
        circuit: norm_bound,
        payload_len: 3,
    });

    let mean_variance = MeanVariance {
        len: 2,
        input_bits: 3,
    };
    let mut wrong_square = mean_variance.encode(&[3, 5]);
    wrong_square[2] += Field128::ONE;
    assert_protocol(&Case {
        honest: [[0, 7], [3, 5], [6, 1]]
            .iter()
            .map(|values| mean_variance.encode(values))
            .collect(),
        invalid: wrong_square,
        circuit: mean_variance,
        payload_len: 4,
    });
}

#[test]
fn aggregate_of_no_contributions_decrypts_to_zero() {
    let (setup, _, server) = roles(&Range::binary(4), 3);
    let aggregate = server.aggregate(&[], &mut rng());
    assert_eq!(
        setup.analyst.decrypt(&aggregate),
        Ok(vec![Field128::ZERO; 3])
    );
}

#[test]
fn server_rejects_foreign_ciphertexts() {
    let mut rng = rng();
    let circuit = Range::binary(4);
    let (_, client, server) = roles(&circuit, 4);
    let input = values(&[1, 0, 0, 1]);
    let ciphertext = client.encrypt(&input, &mut rng).unwrap();
    let short = ciphertext.clone().prefix(4).unwrap();
    assert!(server.validate(short).is_none());

    let foreign_params = Arc::new(Params::generate(TEST_DISCRIMINANT_BITS + 10, &mut rng).unwrap());
    let foreign_setup = Analyst::setup(&foreign_params, circuit.clone(), 4, &mut rng).unwrap();
    let foreign_client = Client::new(circuit, foreign_setup.public_key).unwrap();
    let foreign = foreign_client.encrypt(&input, &mut rng).unwrap();
    assert!(server.validate(foreign).is_none());
    assert!(server.validate(ciphertext).is_some());
}

#[test]
fn setup_errors() {
    let mut rng = rng();
    assert_eq!(
        Analyst::setup(&params(), Range::binary(4), 5, &mut rng).err(),
        Some(PearError::PayloadTooLong {
            payload_len: 5,
            input_len: 4,
        })
    );

    let (setup, client, _) = roles(&Range::binary(4), 4);
    let public_key: &PublicKey<Field128> = &setup.public_key;
    assert_eq!(
        Client::new(Range::binary(8), public_key.clone()).err(),
        Some(PearError::CircuitMismatch)
    );
    assert_eq!(
        Server::new(
            Range::binary(8),
            public_key.clone(),
            setup.verification_key.clone()
        )
        .err(),
        Some(PearError::CircuitMismatch)
    );

    let shorter_input = Range {
        len: 3,
        bounds: 0..=4,
    };
    assert_eq!(shape(shorter_input.clone()), shape(Range::binary(4)));
    assert_eq!(
        Server::new(
            shorter_input,
            public_key.clone(),
            setup.verification_key.clone()
        )
        .err(),
        Some(PearError::CircuitMismatch)
    );

    let (wider_setup, _, _) = roles(&Range::binary(8), 4);
    assert_eq!(shape(Range::binary(8)).1, shape(Range::binary(4)).1);
    assert_ne!(shape(Range::binary(8)).0, shape(Range::binary(4)).0);
    assert_eq!(
        Server::new(
            Range::binary(4),
            public_key.clone(),
            wider_setup.verification_key
        )
        .err(),
        Some(PearError::CircuitMismatch)
    );

    let fewer_queries = Range {
        len: 2,
        bounds: 0..=3,
    };
    let more_queries = NormBound {
        len: 1,
        input_bits: 1,
        norm_bits: 2,
        square_chunk: NonZeroUsize::new(1),
    };
    assert_eq!(
        shape(more_queries.clone()).0,
        shape(fewer_queries.clone()).0
    );
    let (fewer_queries_setup, _, _) = roles(&fewer_queries, 2);
    assert_eq!(
        Server::new(
            more_queries,
            fewer_queries_setup.public_key,
            fewer_queries_setup.verification_key
        )
        .err(),
        Some(PearError::CircuitMismatch)
    );

    assert_eq!(
        client.encrypt(&values(&[1, 0, 1]), &mut rng).err(),
        Some(PearError::Flp(FlpError::InputLength {
            expected: 4,
            actual: 3,
        }))
    );
    let full: Ciphertext<Field128> = client.encrypt(&values(&[1, 0, 1, 0]), &mut rng).unwrap();
    assert_eq!(
        setup.analyst.decrypt(&full).err(),
        Some(PearError::Clt(CltError::DimensionMismatch {
            expected: 4,
            actual: full.dimension(),
        }))
    );
}

#[test]
fn error_messages_are_distinct_lowercase_sentences() {
    let errors = [
        PearError::Clt(CltError::NotInSubgroup),
        PearError::Flp(FlpError::NoOutputs),
        PearError::PayloadTooLong {
            payload_len: 5,
            input_len: 4,
        },
        PearError::CircuitMismatch,
    ];
    let messages: BTreeSet<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    for message in &messages {
        assert!(message.starts_with(char::is_lowercase), "{message}");
        assert!(!message.ends_with('.'), "{message}");
    }
    let sources: Vec<Option<String>> = errors
        .iter()
        .map(|error| error.source().map(ToString::to_string))
        .collect();
    assert_eq!(
        sources,
        [
            Some(CltError::NotInSubgroup.to_string()),
            Some(FlpError::NoOutputs.to_string()),
            None,
            None,
        ]
    );
}

#[test]
fn verification_key_debug_is_redacted() {
    let (setup, _, _) = roles(&Range::binary(4), 3);
    assert_eq!(
        format!("{:?}", setup.verification_key),
        "VerificationKey { queries: 2, payload_len: 3, .. }"
    );
}

#[test]
fn protocol_types_are_thread_safe() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PublicKey<Field128>>();
    assert_send_sync::<niva::clt::MasterSecretKey<Field128>>();
    assert_send_sync::<niva::clt::DecryptionKey<Field128>>();
    assert_send_sync::<niva::clt::FunctionKey<Field128>>();
    assert_send_sync::<Ciphertext<Field128>>();
    assert_send_sync::<Analyst<Field128>>();
    assert_send_sync::<Client<Field128, Range>>();
    assert_send_sync::<Server<Field128, Range>>();
    assert_send_sync::<Contribution<Field128>>();
}
