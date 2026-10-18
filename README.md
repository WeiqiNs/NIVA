# Non-Interactive Verifiable Aggregation in Rust (NIVA)

[![CI](https://github.com/WeiqiNs/NIVA/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WeiqiNs/NIVA/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/WeiqiNs/NIVA/graph/badge.svg)](https://codecov.io/gh/WeiqiNs/NIVA)

Clients each send one encrypted message. The server cannot read them, yet it rejects malformed inputs and sums the
valid ones, and an analyst learns only the total: private aggregation with input validation, in one round.
NIVA implements PEAR from [Non-Interactive Verifiable Aggregation](https://doi.org/10.56553/popets-2025-0171)
(PoPETs 2025), where each client proves its input valid with a fully linear PCP from
[RustFLPCP](https://github.com/WeiqiNs/RustFLPCP) and the server checks the proof through inner-product functional
encryption keys, without decrypting.

## Highlights

- **Any RustFLPCP circuit** as the validity rule: bit vectors, ranges, one-hot votes, set membership, L2 norms.
- **Two encryption schemes behind one `Ipfe` trait:** the class-group scheme of
  [Castagnos, Laguillaumie and Tucker](https://doi.org/10.1007/978-3-030-03329-3_25) that the paper's proof covers,
  and a research-grade lattice scheme after [Bermudo Mera et al. (PKC 2022)](https://eprint.iacr.org/2021/046) that
  encrypts over 130 times faster.
- **Hardened beyond the paper:** decoding neutralises an order-2 class-group element that could make the aggregate
  undecryptable, and the analyst's key decrypts only the payload, never the proof.
- **Pure Rust:** a `parallel` feature, clippy pedantic, and a CI coverage gate that fails on any uncovered line.

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

The third input is not binary, so the server drops it. This is `examples/quickstart.rs`; `examples/lattice.rs` runs
the same protocol with `Lattice::<Field128>::new(Field128::RING_DIMENSION)?` as the scheme.

## Benchmarks

`cargo bench --bench pear --features parallel` on an AMD Ryzen 7 9800X3D (16 threads), 128-bit security for the
class-group scheme and ring dimension 16384 for the lattice scheme, length 100. `norm_bound` is the paper's L2 setting (10-bit inputs, 20-bit norm).

| scheme | rule | client encrypt | server validate | analyst decrypt |
|---|---|---|---|---|
| class group | binary | 1.68 s | 0.17 s | 0.13 s |
| class group | norm_bound | 24.7 s | 0.91 s | 0.14 s |
| lattice | binary | 12.5 ms | 0.27 ms | 2.8 ms |
| lattice | norm_bound | 134 ms | 0.36 ms | 2.8 ms |

The lattice scheme pays in size: its public key grows by 569 KB per vector coordinate, to 3 GB for `norm_bound`.
`cargo run --example costs` prints the sizes per rule.

## Security notes

- Use a cryptographically secure RNG (`rand` 0.8, such as `OsRng`). One query set serves every client, which the
  paper proves sound and zero knowledge; integrity assumes clients do not collude with the server.
- Neither scheme is constant time.
- The lattice scheme is for speed comparisons: its privacy is heuristic (and only at ring dimension 16384; smaller
  ones are for tests), and a client can probe the reused query through its own noise, which a noise ceiling narrows
  but does not close.

## Using it

```toml
[dependencies]
niva = { git = "https://github.com/WeiqiNs/NIVA" }
rust_flpcp = { git = "https://github.com/WeiqiNs/RustFLPCP", rev = "2db89dc351a66cc48f2587f26b5c9e73cb60ecb2" }
rand = "0.8"
```

Pin the same `rust_flpcp` revision as NIVA, since circuits from another revision are a different crate.

## From the paper

The paper's experiments and artifact evaluation used a Sage prototype with FHE and Bulletproofs baselines, kept at
commit [`b6d9767`](https://github.com/WeiqiNs/NIVA/tree/b6d9767); this crate reimplements PEAR in Rust with the
paper's parameters.

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

Related: [RustFLPCP](https://github.com/WeiqiNs/RustFLPCP) (the proof engine), and pairing-based functional
encryption in [Rust](https://github.com/WeiqiNs/RustPFE), [Go](https://github.com/WeiqiNs/GoPFE),
[C++](https://github.com/WeiqiNs/LibPFE) and [CUDA](https://github.com/WeiqiNs/CudaPFE).

## Build and test

```sh
cargo test --all && cargo clippy --all --all-targets -- -D warnings
cargo llvm-cov --all --fail-uncovered-lines 0 && cargo bench --bench pear
```
