use ark_ff::UniformRand;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, SeedableRng};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use niva::Field128;
use niva::lattice::{
    self, Ciphertext, DecryptionKey, FunctionKey, LatticeField, Params, PublicKey,
};
use rust_flpcp::{Circuit, Flp, NormBound, Range};
use std::cell::OnceCell;
use std::hint::black_box;
use std::sync::Arc;

struct Config {
    label: &'static str,
    vector_len: usize,
    query_count: usize,
    payload_len: usize,
}

struct Fixture {
    public_key: PublicKey<Field128>,
    payload_key: PublicKey<Field128>,
    message: Vec<Field128>,
    keys: Vec<FunctionKey<Field128>>,
    ciphertext: Ciphertext<Field128>,
    payload: Ciphertext<Field128>,
    decryption_key: DecryptionKey<Field128>,
}

fn config<C: Circuit<Field128>>(label: &'static str, circuit: C, payload_len: usize) -> Config {
    let flp = Flp::<Field128, C>::new(circuit).unwrap();
    Config {
        label,
        vector_len: flp.vector_len(),
        query_count: flp.query_count(),
        payload_len,
    }
}

fn random(len: usize, rng: &mut impl Rng) -> Vec<Field128> {
    (0..len).map(|_| Field128::rand(rng)).collect()
}

fn inner_product(x: &[Field128], y: &[Field128]) -> Field128 {
    x.iter().zip(y).map(|(a, b)| *a * b).sum()
}

fn fixture(params: &Arc<Params<Field128>>, config: &Config) -> Fixture {
    let mut rng = StdRng::seed_from_u64(1);
    let (public_key, secret_key) = lattice::setup(params, config.vector_len, &mut rng).unwrap();
    let message = random(config.vector_len, &mut rng);
    let ciphertext = public_key.encrypt(&message, &mut rng).unwrap();
    let vectors: Vec<Vec<Field128>> = (0..config.query_count)
        .map(|_| random(config.vector_len, &mut rng))
        .collect();
    let slices: Vec<&[Field128]> = vectors.iter().map(Vec::as_slice).collect();
    let (keys, decryption_key) = secret_key.function_keys(&slices).unwrap();
    for (key, vector) in keys.iter().zip(&slices) {
        assert_eq!(
            public_key.eval(key, &ciphertext),
            Ok(inner_product(&message, vector)),
            "{}",
            config.label
        );
    }
    let payload_len = config.payload_len;
    let decryption_key = decryption_key.prefix(payload_len).unwrap();
    let payload_key = public_key.prefix(payload_len).unwrap();
    let payload = ciphertext.clone().prefix(payload_len).unwrap();
    let doubled: Vec<Field128> = message[..payload_len].iter().map(|x| *x + x).collect();
    assert_eq!(
        decryption_key.decrypt(&payload_key.add(&payload, &payload).unwrap()),
        Ok(doubled),
        "{}",
        config.label
    );
    Fixture {
        public_key,
        payload_key,
        message,
        keys,
        ciphertext,
        payload,
        decryption_key,
    }
}

fn bench_config(c: &mut Criterion, params: &Arc<Params<Field128>>, config: &Config) {
    let mut group = c.benchmark_group("lattice");
    group.sample_size(10);
    let mut rng = StdRng::seed_from_u64(2);
    let cell = OnceCell::new();
    let fixture = || cell.get_or_init(|| fixture(params, config));
    let id = |name| BenchmarkId::new(name, config.label);
    group.bench_function(id("setup"), |b| {
        b.iter(|| lattice::setup(params, config.vector_len, &mut rng).unwrap());
    });
    group.bench_function(id("encrypt"), |b| {
        let Fixture {
            public_key,
            message,
            ..
        } = fixture();
        b.iter(|| public_key.encrypt(black_box(message), &mut rng).unwrap());
    });
    group.bench_function(id("eval"), |b| {
        let Fixture {
            public_key,
            keys,
            ciphertext,
            ..
        } = fixture();
        b.iter(|| {
            keys.iter()
                .map(|key| public_key.eval(key, black_box(ciphertext)).unwrap())
                .collect::<Vec<Field128>>()
        });
    });
    group.bench_function(id("add"), |b| {
        let Fixture {
            payload_key,
            payload,
            ..
        } = fixture();
        b.iter(|| payload_key.add(black_box(payload), payload).unwrap());
    });
    group.bench_function(id("decrypt"), |b| {
        let Fixture {
            decryption_key,
            payload,
            ..
        } = fixture();
        b.iter(|| decryption_key.decrypt(black_box(payload)).unwrap());
    });
    group.finish();
}

fn backend(c: &mut Criterion) {
    let params = Arc::new(Params::new(Field128::RING_DIMENSION).unwrap());
    let norm_bound = NormBound {
        len: 100,
        input_bits: 10,
        norm_bits: 20,
        square_chunk: None,
    };
    for config in [
        config("binary_10", Range::binary(10), 10),
        config("binary_100", Range::binary(100), 100),
        config("norm_bound_100", norm_bound, 100),
    ] {
        bench_config(c, &params, &config);
    }
}

criterion_group!(benches, backend);
criterion_main!(benches);
