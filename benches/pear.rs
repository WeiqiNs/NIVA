use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use criterion::measurement::WallTime;
use criterion::{
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main,
};
use niva::clt::{Clt, DISCRIMINANT_BITS};
use niva::lattice::{Lattice, LatticeField};
use niva::pear::{Analyst, Contribution, Server};
use niva::{Field128, Ipfe, PearError};
use rust_flpcp::{Circuit, Flp, NormBound, Range};
use std::cell::OnceCell;
use std::hint::black_box;
use std::sync::Arc;

const LENS: [usize; 4] = [10, 25, 50, 100];

struct Config<C> {
    len: usize,
    circuit: C,
    input: Vec<Field128>,
    payload_len: usize,
}

struct Fixture<S: Ipfe<Field128>, C: Circuit<Field128>> {
    analyst: Analyst<Field128, S>,
    public_key: S::PublicKey,
    server: Server<Field128, C, S>,
    flp: Flp<Field128, C>,
    vector: Vec<Field128>,
    ciphertext: S::Ciphertext,
    contributions: [Contribution<Field128, S>; 2],
    aggregate: S::Ciphertext,
}

fn measurement(len: usize, modulus: u64) -> Vec<u64> {
    (0..len as u64).map(|index| index % modulus).collect()
}

fn fixture<S: Ipfe<Field128>, C: Circuit<Field128> + Clone>(
    scheme: &Arc<S>,
    config: &Config<C>,
) -> Fixture<S, C>
where
    PearError: From<S::Error>,
{
    let mut rng = StdRng::seed_from_u64(1);
    let circuit = &config.circuit;
    let setup = Analyst::setup(scheme, circuit.clone(), config.payload_len, &mut rng).unwrap();
    let server = Server::new(
        circuit.clone(),
        setup.public_key.clone(),
        setup.verification_key.clone(),
    )
    .unwrap();
    let flp = Flp::new(circuit.clone()).unwrap();
    let vector = flp.prove(&config.input, &mut rng).unwrap();
    let ciphertext = S::encrypt(&setup.public_key.0, &vector, &mut rng).unwrap();
    let contribution = server.validate(ciphertext.clone()).unwrap();
    let contributions = [contribution.clone(), contribution];
    let aggregate = server.aggregate(&contributions, &mut rng).unwrap();
    let doubled: Vec<Field128> = config.input[..config.payload_len]
        .iter()
        .map(|x| *x + x)
        .collect();
    assert_eq!(
        setup.analyst.decrypt(&aggregate),
        Ok(doubled),
        "{}",
        config.len
    );
    Fixture {
        analyst: setup.analyst,
        public_key: setup.public_key.0,
        server,
        flp,
        vector,
        ciphertext,
        contributions,
        aggregate,
    }
}

fn bench_config<S: Ipfe<Field128>, C: Circuit<Field128> + Clone>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    scheme: &Arc<S>,
    config: &Config<C>,
) where
    PearError: From<S::Error>,
{
    let mut rng = StdRng::seed_from_u64(2);
    let cell = OnceCell::new();
    let fixture = || cell.get_or_init(|| fixture(scheme, config));
    let id = |name| BenchmarkId::new(name, config.len);
    group.bench_function(id("setup"), |b| {
        b.iter(|| {
            Analyst::setup(scheme, config.circuit.clone(), config.payload_len, &mut rng).unwrap()
        });
    });
    group.bench_function(id("prove"), |b| {
        let flp = &fixture().flp;
        b.iter(|| flp.prove(black_box(&config.input), &mut rng).unwrap());
    });
    group.bench_function(id("encrypt"), |b| {
        let Fixture {
            public_key, vector, ..
        } = fixture();
        b.iter(|| S::encrypt(public_key, black_box(vector), &mut rng).unwrap());
    });
    group.bench_function(id("validate"), |b| {
        let Fixture {
            server, ciphertext, ..
        } = fixture();
        b.iter_batched(
            || ciphertext.clone(),
            |ciphertext| server.validate(ciphertext).unwrap(),
            BatchSize::LargeInput,
        );
    });
    group.bench_function(id("aggregate"), |b| {
        let Fixture {
            server,
            contributions,
            ..
        } = fixture();
        b.iter(|| {
            server
                .aggregate(black_box(contributions), &mut rng)
                .unwrap()
        });
    });
    group.bench_function(id("decrypt"), |b| {
        let Fixture {
            analyst, aggregate, ..
        } = fixture();
        b.iter(|| analyst.decrypt(black_box(aggregate)).unwrap());
    });
}

fn bench_rule<S: Ipfe<Field128>, C: Circuit<Field128> + Clone>(
    c: &mut Criterion,
    scheme: &Arc<S>,
    label: &str,
    config: impl Fn(usize) -> Config<C>,
) where
    PearError: From<S::Error>,
{
    let mut group = c.benchmark_group(label);
    group.sample_size(10);
    for len in LENS {
        bench_config(&mut group, scheme, &config(len));
    }
    group.finish();
}

fn bench_backend<S: Ipfe<Field128>>(c: &mut Criterion, backend: &str, scheme: &Arc<S>)
where
    PearError: From<S::Error>,
{
    bench_rule(c, scheme, &format!("{backend}/binary"), |len| Config {
        len,
        circuit: Range::binary(len),
        input: measurement(len, 2)
            .into_iter()
            .map(Field128::from)
            .collect(),
        payload_len: len,
    });
    bench_rule(c, scheme, &format!("{backend}/norm_bound"), |len| {
        let circuit = NormBound {
            len,
            input_bits: 10,
            norm_bits: 20,
            square_chunk: None,
        };
        Config {
            len,
            input: circuit.encode(&measurement(len, 64)),
            circuit,
            payload_len: len,
        }
    });
}

fn backends(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0);
    let clt = Arc::new(Clt::generate(DISCRIMINANT_BITS, &mut rng).unwrap());
    bench_backend(c, "clt", &clt);
    let lattice = Arc::new(Lattice::new(Field128::RING_DIMENSION).unwrap());
    bench_backend(c, "lattice", &lattice);
}

criterion_group!(benches, backends);
criterion_main!(benches);
