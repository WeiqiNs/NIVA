mod common;

use ark_ff::{AdditiveGroup, Field, UniformRand};
use common::{params, rng};
use niva::clt::{self, DISCRIMINANT_BITS, Params};
use niva::{CltError, Field128};
use std::collections::BTreeSet;
use std::sync::Arc;

fn inner_product(x: &[Field128], y: &[Field128]) -> Field128 {
    x.iter().zip(y).map(|(a, b)| *a * b).sum()
}

#[test]
fn decrypt_and_eval_recover_plaintext_and_inner_products() {
    let mut rng = rng();
    let (public_key, secret_key) = clt::setup(&params(), 5, &mut rng);
    let message = [
        Field128::ZERO,
        Field128::ONE,
        -Field128::ONE,
        Field128::from(2u8).pow([100]),
        -Field128::from(2u8),
    ];
    let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();
    assert_eq!(secret_key.decrypt(&ciphertext), Ok(message.to_vec()));

    let unit = [
        Field128::ONE,
        Field128::ZERO,
        Field128::ZERO,
        Field128::ZERO,
        Field128::ZERO,
    ];
    let negated = [-Field128::ONE; 5];
    let random: Vec<Field128> = (0..5).map(|_| Field128::rand(&mut rng)).collect();
    let vectors = [unit.as_slice(), negated.as_slice(), random.as_slice()];
    let keys = secret_key.function_keys(&vectors).unwrap();
    for (key, vector) in keys.iter().zip(vectors) {
        assert_eq!(
            public_key.eval(key, &ciphertext),
            Ok(inner_product(&message, vector))
        );
    }
}

#[test]
fn add_is_homomorphic_with_wraparound() {
    let mut rng = rng();
    let (public_key, secret_key) = clt::setup(&params(), 2, &mut rng);
    let left = public_key
        .encrypt(&[-Field128::ONE, Field128::from(5u8)], &mut rng)
        .unwrap();
    let right = public_key
        .encrypt(&[Field128::from(2u8), -Field128::from(5u8)], &mut rng)
        .unwrap();
    let sum = public_key.add(&left, &right).unwrap();
    assert_eq!(
        secret_key.decrypt(&sum),
        Ok(vec![Field128::ONE, Field128::ZERO])
    );
}

#[test]
fn prefix_restricts_keys_and_ciphertexts() {
    let mut rng = rng();
    let (public_key, secret_key) = clt::setup(&params(), 5, &mut rng);
    let message: Vec<Field128> = (1..=5u8).map(Field128::from).collect();
    let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();

    let short_secret = secret_key.prefix(2).unwrap();
    assert_eq!(
        short_secret.decrypt(&ciphertext.clone().prefix(2).unwrap()),
        Ok(message[..2].to_vec())
    );
    let short_public = public_key.prefix(2).unwrap();
    let short_ciphertext = short_public.encrypt(&message[..2], &mut rng).unwrap();
    assert_eq!(
        short_secret.decrypt(&short_ciphertext),
        Ok(message[..2].to_vec())
    );

    let too_long = Some(CltError::PrefixTooLong {
        len: 6,
        dimension: 5,
    });
    assert_eq!(public_key.prefix(6).err(), too_long);
    assert_eq!(secret_key.prefix(6).err(), too_long);
    assert_eq!(ciphertext.prefix(6).err(), too_long);
}

#[test]
fn dimension_mismatches_are_errors() {
    let mut rng = rng();
    let (public_key, secret_key) = clt::setup(&params(), 3, &mut rng);
    let mismatch = Some(CltError::DimensionMismatch {
        expected: 3,
        actual: 2,
    });
    let message = [Field128::ONE; 3];
    let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();
    let short = public_key
        .prefix(2)
        .unwrap()
        .encrypt(&message[..2], &mut rng)
        .unwrap();
    let key = &secret_key.function_keys(&[message.as_slice()]).unwrap()[0];

    assert_eq!(public_key.encrypt(&message[..2], &mut rng).err(), mismatch);
    let vectors = [message.as_slice(), &message[..2]];
    assert_eq!(secret_key.function_keys(&vectors).err(), mismatch);
    assert_eq!(public_key.eval(key, &short).err(), mismatch);
    assert_eq!(public_key.add(&ciphertext, &short).err(), mismatch);
    assert_eq!(secret_key.decrypt(&short).err(), mismatch);
}

#[test]
fn dependent_function_vectors_rejected() {
    let mut rng = rng();
    let (_, secret_key) = clt::setup(&params(), 3, &mut rng);
    let vector: Vec<Field128> = (0..3).map(|_| Field128::rand(&mut rng)).collect();
    let doubled: Vec<Field128> = vector.iter().map(Field128::double).collect();
    let zero = [Field128::ZERO; 3];
    for vectors in [
        [vector.as_slice(), doubled.as_slice()].as_slice(),
        &[zero.as_slice()],
    ] {
        assert_eq!(
            secret_key.function_keys(vectors).err(),
            Some(CltError::DependentFunctionVectors)
        );
    }
}

#[test]
fn error_messages_are_distinct_lowercase_sentences() {
    let errors = [
        CltError::DiscriminantTooSmall {
            bits: 258,
            minimum: 259,
        },
        CltError::DimensionMismatch {
            expected: 3,
            actual: 2,
        },
        CltError::PrefixTooLong {
            len: 6,
            dimension: 5,
        },
        CltError::DependentFunctionVectors,
        CltError::NotInSubgroup,
    ];
    let messages: BTreeSet<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    for message in &messages {
        assert!(message.starts_with(char::is_lowercase), "{message}");
        assert!(!message.ends_with('.'), "{message}");
    }
}

#[test]
#[ignore = "generates full-size parameters"]
fn full_size_round_trip() {
    let mut rng = rng();
    let params = Arc::new(Params::<Field128>::generate(DISCRIMINANT_BITS, &mut rng).unwrap());
    assert_eq!(params.discriminant_bits(), 1827);
    let (public_key, secret_key) = clt::setup(&params, 3, &mut rng);
    let message = [Field128::from(7u8), -Field128::ONE, Field128::ZERO];
    let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();
    assert_eq!(secret_key.decrypt(&ciphertext), Ok(message.to_vec()));
    let vector = [Field128::ONE, Field128::from(2u8), Field128::from(3u8)];
    let key = &secret_key.function_keys(&[vector.as_slice()]).unwrap()[0];
    assert_eq!(
        public_key.eval(key, &ciphertext),
        Ok(inner_product(&message, &vector))
    );
}
