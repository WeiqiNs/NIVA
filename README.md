# Non-Interactive Verifiable Aggregation in Rust (NIVA)

[![CI](https://github.com/WeiqiNs/NIVA/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WeiqiNs/NIVA/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/WeiqiNs/NIVA/graph/badge.svg)](https://codecov.io/gh/WeiqiNs/NIVA)

Many clients each send one encrypted message. The server cannot read them, yet it throws out every malformed input
and adds up the valid ones, and an analyst learns only the sum. That is private aggregation with input validation, as
in federated analytics or private telemetry, in a single round and with no interaction between clients.

NIVA implements PEAR from [Non-Interactive Verifiable Aggregation](https://doi.org/10.56553/popets-2025-0171)
(PoPETs 2025): each client attaches a fully linear PCP proof from [RustFLPCP](https://github.com/WeiqiNs/RustFLPCP)
and encrypts both under inner-product functional encryption, so the server checks the proof through function keys
for the proof's linear queries without ever seeing the input.

## Highlights

- **Any validity rule.** Clients prove membership in any RustFLPCP circuit: bit vectors, ranges, one-hot votes,
  set membership, or bounded L2 norms for federated learning.
- **Two encryption schemes behind one interface.** The protocol is generic over the `Ipfe` trait, with the
  class-group scheme of [Castagnos, Laguillaumie and Tucker (Asiacrypt 2018)](https://doi.org/10.1007/978-3-030-03329-3_25)
  that the paper's security proof covers, and a research-grade lattice scheme that encrypts 50 to 180 times faster.
- **Hardened beyond the paper.** Decoding neutralises an order-2 class-group element that a client could use to make
  the aggregate undecryptable, and function keys can only be issued in one batch, so no two keys combine into a third.
- **Pure Rust, parallel and tested.** No C toolchain, a `parallel` feature over all cores, clippy pedantic, and a CI
  coverage gate that fails on any uncovered line.

## Quick start

```rust
use niva::clt::{Clt, DISCRIMINANT_BITS};
use niva::pear::{Analyst, Client, Server};
use niva::Field128;
use rand::rngs::OsRng;
use rust_flpcp::Range;
use std::sync::Arc;

let rng = &mut OsRng;
let scheme = Arc::new(Clt::<Field128>::generate(DISCRIMINANT_BITS, rng)?);
let circuit = Range::binary(4);
let setup = Analyst::setup(&scheme, circuit.clone(), 4, rng)?;
let client = Client::new(circuit.clone(), setup.public_key.clone())?;
let server = Server::new(circuit, setup.public_key, setup.verification_key)?;

let mut contributions = Vec::new();
for input in [[1u64, 0, 1, 1], [0, 1, 1, 0], [2, 0, 0, 1]] {
    let ciphertext = client.encrypt(&input.map(Field128::from), rng)?;
    contributions.extend(server.validate(ciphertext));
}
assert_eq!(contributions.len(), 2);

let aggregate = server.aggregate(&contributions, rng)?;
let sum = setup.analyst.decrypt(&aggregate)?;
assert_eq!(sum, [1u64, 1, 2, 1].map(Field128::from));
```

The third client's input is not binary, so the server rejects it without decrypting. This is
`examples/quickstart.rs`; `examples/lattice.rs` runs the same protocol on the lattice scheme by changing one line:

```rust
use niva::lattice::{Lattice, LatticeField};

let scheme = Arc::new(Lattice::<Field128>::new(Field128::RING_DIMENSION)?);
```

## How it works

- `Analyst::setup` creates encryption keys as long as the proof vector, draws one set of proof queries, gives the
  server a function key per query, and keeps a decryption key for the payload only.
- `Client::encrypt` proves its input satisfies the circuit and encrypts input and proof together.
- `Server::validate` evaluates the function keys on the ciphertext, which yields the proof's query answers, accepts
  only if the proof checks out, and keeps just the payload. `Server::aggregate` adds the kept ciphertexts
  homomorphically together with a fresh encryption of zeros.
- `Analyst::decrypt` turns the aggregate into the sum of the valid payloads.

## Benchmarks

`cargo bench --bench pear --features parallel` on an AMD Ryzen 7 9800X3D (8 cores, 16 threads), at 128-bit security
for the class-group scheme (`clt`) and ring dimension 16384 for the lattice scheme. `binary` is `Range::binary(len)`;
`norm_bound` is `NormBound { len, input_bits: 10, norm_bits: 20, .. }`, the paper's setting. Proving takes under a
millisecond everywhere.

| scheme | rule | len | client encrypt | server validate | aggregate 2 | analyst decrypt |
|---|---|---|---|---|---|---|
| clt | binary | 10 | 0.22 s | 0.08 s | 0.08 s | 0.06 s |
| clt | binary | 100 | 1.68 s | 0.17 s | 0.51 s | 0.13 s |
| clt | norm_bound | 10 | 3.05 s | 0.26 s | 0.08 s | 0.06 s |
| clt | norm_bound | 100 | 24.7 s | 0.91 s | 0.51 s | 0.14 s |
| lattice | binary | 10 | 4.4 ms | 0.26 ms | 4.0 ms | 0.41 ms |
| lattice | binary | 100 | 12.5 ms | 0.27 ms | 6.3 ms | 2.8 ms |
| lattice | norm_bound | 10 | 20.1 ms | 0.28 ms | 4.0 ms | 0.41 ms |
| lattice | norm_bound | 100 | 134 ms | 0.36 ms | 6.0 ms | 2.8 ms |

The class-group scheme costs one exponentiation per vector coordinate, so encryption dominates. The lattice scheme
pays in size instead: ciphertexts of 0.57 to 0.75 MB and a public key of 569 KB per coordinate, 3 GB for
`norm_bound` at length 100. `cargo run --example costs` prints the sizes for each rule.

## Security notes

- Pass a cryptographically secure generator (`rand` 0.8, such as `OsRng`).
- One query set is reused for every client, which the paper proves sound and zero knowledge.
- The server learns the queries, so integrity holds only against clients that do not collude with the server, and
  the analyst must keep its decryption key to itself.
- Neither scheme handles secrets in constant time.
- The lattice scheme is for speed comparisons. Its privacy is heuristic, with parameters from the lattice estimator
  and no reduction to PEAR's privacy game, and its integrity assumes clients encrypt honestly: a client can probe the
  reused query through its own noise (a key-reuse reaction attack), which a noise ceiling narrows but does not close.

## Using it

```toml
[dependencies]
niva = { git = "https://github.com/WeiqiNs/NIVA" }
rust_flpcp = { git = "https://github.com/WeiqiNs/RustFLPCP", rev = "2db89dc351a66cc48f2587f26b5c9e73cb60ecb2" }
rand = "0.8"
```

Pin the same `rust_flpcp` revision as NIVA's `Cargo.toml`, since circuits from a different revision are a separate
crate. The `parallel` feature spreads exponentiations, validation and aggregation over threads.

## From the paper

The paper's experiments ran on a Sage prototype with FHE and Bulletproofs baselines, which remains in this
repository's history at commit `b6d9767`. This crate reimplements PEAR from scratch in Rust, with the paper's
parameters, and adds the lattice scheme for comparison.

```bibtex
@article{acharya2025niva,
  title   = {Non-Interactive Verifiable Aggregation},
  author  = {Acharya, Ojaswi and Biswas, Suvasree and Feng, Weiqi and O'Neill, Adam and Yerukhimovich, Arkady},
  journal = {Proceedings on Privacy Enhancing Technologies},
  volume  = {2025},
  number  = {4},
  pages   = {1055--1074},
  year    = {2025},
  doi     = {10.56553/popets-2025-0171}
}
```

## Related

- [RustFLPCP](https://github.com/WeiqiNs/RustFLPCP): the fully linear PCP engine the proofs come from.
- [RustPFE](https://github.com/WeiqiNs/RustPFE), [GoPFE](https://github.com/WeiqiNs/GoPFE),
  [LibPFE](https://github.com/WeiqiNs/LibPFE) and [CudaPFE](https://github.com/WeiqiNs/CudaPFE): pairing-based
  functional encryption in Rust, Go, C++ and CUDA.

## Build and test

```sh
cargo test --all
cargo clippy --all --all-targets -- -D warnings
cargo llvm-cov --all --fail-uncovered-lines 0
cargo bench --bench pear
```
