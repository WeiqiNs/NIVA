# Non-Interactive Verifiable Aggregation (NIVA)

[![CI](https://github.com/WeiqiNs/NIVA/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WeiqiNs/NIVA/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/WeiqiNs/NIVA/graph/badge.svg)](https://codecov.io/gh/WeiqiNs/NIVA)

NIVA implements PEAR from
[Non-Interactive Verifiable Aggregation (PoPETs 2025)](https://doi.org/10.56553/popets-2025-0171): clients send
one encrypted message each, a server rejects malformed inputs without decrypting them and adds up the valid ones,
and an analyst learns only the sum. Each client encrypts its input together with a fully linear PCP proof from
[RustFLPCP](https://github.com/WeiqiNs/RustFLPCP) under the inner-product functional encryption scheme of
[Castagnos, Laguillaumie and Tucker (Asiacrypt 2018)](https://doi.org/10.1007/978-3-030-03329-3_25) over class
groups; the server holds function keys for the proof's linear queries, so it checks the proof on ciphertexts.

```rust
use niva::clt::{DISCRIMINANT_BITS, Params};
use niva::pear::{Analyst, Client, Server};
use niva::Field128;
use rand::rngs::OsRng;
use rust_flpcp::Range;
use std::sync::Arc;

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
```

This is `examples/quickstart.rs`.

## How it works

- `Analyst::setup` creates encryption keys as long as the proof vector, draws one set of proof queries, and gives
  the server a function key per query. It keeps a decryption key for the payload, the prefix of the input it may
  learn, and nothing else.
- `Client::encrypt` proves that its input satisfies the circuit and encrypts input and proof together.
- `Server::validate` evaluates the function keys on the ciphertext, which yields the query answers, and accepts the
  ciphertext only if the proof checks out; it keeps just the payload part. `Server::aggregate` multiplies the kept
  ciphertexts together with a fresh encryption of zeros.
- `Analyst::decrypt` turns the aggregate into the sum of the valid payloads.

Run `cargo run --example costs` for each rule's ciphertext size and query count.

## Security notes

- Pass a cryptographically secure generator (`rand` 0.8, such as `OsRng`).
- One query set is reused for every client, which the paper proves sound and zero knowledge (reusable soundness and
  reusable strong honest-verifier zero knowledge).
- The server learns the queries, so integrity holds only against clients that do not collude with the server. The
  analyst must keep its decryption key to itself.
- Function keys come from one batch: `clt::MasterSecretKey::function_keys` consumes the master key and returns a
  decryption key that cannot issue more, because keys from separate batches could combine into an unauthorised one.
- Secret exponents are not handled in constant time.

## Using it

```toml
[dependencies]
niva = { git = "https://github.com/WeiqiNs/NIVA" }
rust_flpcp = { git = "https://github.com/WeiqiNs/RustFLPCP", rev = "2db89dc351a66cc48f2587f26b5c9e73cb60ecb2" }
rand = "0.8"
```

Circuits come from `rust_flpcp`, so pin the same revision as NIVA's `Cargo.toml`; a different one is a separate
crate whose circuits NIVA's types do not accept. The `parallel` feature spreads exponentiations,
validation and aggregation over threads. Everything is pure Rust; no C toolchain is needed.

## Benchmarks

`cargo bench --bench pear --features parallel` on an AMD Ryzen 7 9800X3D (8 cores, 16 threads), with
128-bit security (`DISCRIMINANT_BITS`). `binary` is `Range::binary(len)`; `norm_bound` is
`NormBound { len, input_bits: 10, norm_bits: 20, .. }`, the paper's setting. Proving takes under a millisecond;
encryption dominates the client because it costs one class-group exponentiation per vector coordinate.

| rule | len | client encrypt | server validate | aggregate 2 | analyst decrypt |
|---|---|---|---|---|---|
| binary | 10 | 0.22 s | 0.08 s | 0.08 s | 0.06 s |
| binary | 100 | 1.68 s | 0.17 s | 0.51 s | 0.13 s |
| norm_bound | 10 | 3.05 s | 0.26 s | 0.08 s | 0.06 s |
| norm_bound | 100 | 24.7 s | 0.91 s | 0.51 s | 0.14 s |

On one thread (without `parallel`), `binary` at length 100 takes 16.5 s to encrypt and 0.50 s to validate.

## Build and test

```sh
cargo test --all
cargo clippy --all --all-targets -- -D warnings
cargo llvm-cov --all --fail-uncovered-lines 0
cargo bench --bench pear
```
