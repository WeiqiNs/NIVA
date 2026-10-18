mod common;

use ark_ff::{AdditiveGroup, Field, UniformRand};
use common::{inner_product, lattice, rng};
use niva::lattice::{self, Lattice, LatticeField, MAX_DIMENSION};
use niva::{Field128, LatticeError};
use std::collections::BTreeSet;
use std::sync::Arc;

#[test]
fn foreign_ring_dimension_is_rejected() {
    let mut rng = rng();
    let local = lattice();
    let foreign = Arc::new(Lattice::new(local.ring_dimension() * 2).unwrap());
    let mismatch = Some(LatticeError::RingDimensionMismatch {
        expected: local.ring_dimension(),
        actual: foreign.ring_dimension(),
    });
    let message = [Field128::ONE, Field128::ZERO, -Field128::ONE];
    let vector = [Field128::ONE; 3];

    let (public_key, secret_key) = lattice::setup(&local, 3, &mut rng).unwrap();
    let (keys, decryption_key) = secret_key.function_keys(&[vector.as_slice()]).unwrap();
    let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();

    let (foreign_public_key, foreign_secret_key) = lattice::setup(&foreign, 3, &mut rng).unwrap();
    let (foreign_keys, _) = foreign_secret_key
        .function_keys(&[vector.as_slice()])
        .unwrap();
    let foreign_ciphertext = foreign_public_key.encrypt(&message, &mut rng).unwrap();

    assert_eq!(
        public_key.eval(&keys[0], &foreign_ciphertext).err(),
        mismatch
    );
    assert_eq!(
        public_key.eval(&foreign_keys[0], &ciphertext).err(),
        mismatch
    );
    assert_eq!(
        public_key.add(&ciphertext, &foreign_ciphertext).err(),
        mismatch
    );
    assert_eq!(
        public_key.add(&foreign_ciphertext, &ciphertext).err(),
        mismatch
    );
    assert_eq!(decryption_key.decrypt(&foreign_ciphertext).err(), mismatch);
}

#[test]
fn decrypt_and_eval_recover_plaintext_and_inner_products() {
    let mut rng = rng();
    let (public_key, secret_key) = lattice::setup(&lattice(), 5, &mut rng).unwrap();
    let message = [
        Field128::ZERO,
        Field128::ONE,
        -Field128::ONE,
        Field128::from(2u8).pow([100]),
        -Field128::from(2u8),
    ];
    let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();

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
    let (keys, decryption_key) = secret_key.function_keys(&vectors).unwrap();
    assert_eq!(decryption_key.decrypt(&ciphertext), Ok(message.to_vec()));
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
    let (public_key, secret_key) = lattice::setup(&lattice(), 4, &mut rng).unwrap();
    let vector: Vec<Field128> = (0..4).map(|_| Field128::rand(&mut rng)).collect();
    let (keys, decryption_key) = secret_key.function_keys(&[vector.as_slice()]).unwrap();
    let messages: Vec<Vec<Field128>> = (0..64)
        .map(|_| (0..4).map(|_| Field128::rand(&mut rng)).collect())
        .collect();
    let ciphertexts: Vec<_> = messages
        .iter()
        .map(|message| public_key.encrypt(message, &mut rng).unwrap())
        .collect();
    let aggregate = ciphertexts[1..]
        .iter()
        .fold(ciphertexts[0].clone(), |sum, ciphertext| {
            public_key.add(&sum, ciphertext).unwrap()
        });
    let expected: Vec<Field128> = (0..4)
        .map(|index| messages.iter().map(|message| message[index]).sum())
        .collect();
    assert_eq!(decryption_key.decrypt(&aggregate), Ok(expected.clone()));
    assert_eq!(
        public_key.eval(&keys[0], &aggregate),
        Ok(inner_product(&expected, &vector))
    );
}

#[test]
fn prefix_restricts_keys_and_ciphertexts() {
    let mut rng = rng();
    let (public_key, secret_key) = lattice::setup(&lattice(), 5, &mut rng).unwrap();
    let message: Vec<Field128> = (1..=5u8).map(Field128::from).collect();
    let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();

    let (_, decryption_key) = secret_key.function_keys(&[]).unwrap();
    let short_secret = decryption_key.prefix(2).unwrap();
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

    let too_long = Some(LatticeError::PrefixTooLong {
        len: 6,
        dimension: 5,
    });
    assert_eq!(public_key.prefix(6).err(), too_long);
    assert_eq!(decryption_key.prefix(6).err(), too_long);
    assert_eq!(ciphertext.prefix(6).err(), too_long);
}

#[test]
fn dimension_mismatches_are_errors() {
    let mut rng = rng();
    let (public_key, secret_key) = lattice::setup(&lattice(), 3, &mut rng).unwrap();
    let mismatch = Some(LatticeError::DimensionMismatch {
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
    let (keys, decryption_key) = secret_key.function_keys(&[message.as_slice()]).unwrap();

    assert_eq!(public_key.encrypt(&message[..2], &mut rng).err(), mismatch);
    let (_, other_secret_key) = lattice::setup(&lattice(), 3, &mut rng).unwrap();
    let vectors = [message.as_slice(), &message[..2]];
    assert_eq!(other_secret_key.function_keys(&vectors).err(), mismatch);
    assert_eq!(public_key.eval(&keys[0], &short).err(), mismatch);
    assert_eq!(public_key.add(&ciphertext, &short).err(), mismatch);
    assert_eq!(decryption_key.decrypt(&short).err(), mismatch);

    assert_eq!(
        lattice::setup(&lattice(), MAX_DIMENSION + 1, &mut rng).err(),
        Some(LatticeError::DimensionTooLarge {
            dimension: 8193,
            maximum: 8192,
        })
    );
}

#[test]
fn dependent_function_vectors_rejected() {
    let mut rng = rng();
    let vector: Vec<Field128> = (0..3).map(|_| Field128::rand(&mut rng)).collect();
    let doubled: Vec<Field128> = vector.iter().map(Field128::double).collect();
    let (_, secret_key) = lattice::setup(&lattice(), 3, &mut rng).unwrap();
    assert_eq!(
        secret_key
            .function_keys(&[vector.as_slice(), doubled.as_slice()])
            .err(),
        Some(LatticeError::DependentFunctionVectors)
    );
}

#[test]
fn error_messages_are_distinct_lowercase_sentences() {
    let errors = [
        LatticeError::RingDimension { dimension: 1000 },
        LatticeError::DimensionTooLarge {
            dimension: 8193,
            maximum: 8192,
        },
        LatticeError::DimensionMismatch {
            expected: 3,
            actual: 2,
        },
        LatticeError::PrefixTooLong {
            len: 6,
            dimension: 5,
        },
        LatticeError::RingDimensionMismatch {
            expected: 1024,
            actual: 2048,
        },
        LatticeError::DependentFunctionVectors,
        LatticeError::NoiseTooLarge,
    ];
    let messages: BTreeSet<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
    for message in &messages {
        assert!(message.starts_with(char::is_lowercase), "{message}");
        assert!(!message.ends_with('.'), "{message}");
    }
}

#[test]
#[ignore = "builds full-size keys"]
fn full_size_round_trip() {
    let mut rng = rng();
    let scheme = Arc::new(Lattice::<Field128>::new(Field128::RING_DIMENSION).unwrap());
    assert_eq!(scheme.ring_dimension(), 16384);
    let (public_key, secret_key) = lattice::setup(&scheme, 356, &mut rng).unwrap();
    let message: Vec<Field128> = (0..356).map(|_| Field128::rand(&mut rng)).collect();
    let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();
    let vector: Vec<Field128> = (0..356).map(|_| Field128::rand(&mut rng)).collect();
    let (keys, decryption_key) = secret_key.function_keys(&[vector.as_slice()]).unwrap();
    assert_eq!(decryption_key.decrypt(&ciphertext), Ok(message.clone()));
    assert_eq!(
        public_key.eval(&keys[0], &ciphertext),
        Ok(inner_product(&message, &vector))
    );
}
