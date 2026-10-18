use ark_ff::PrimeField;
use niva::Field128;
use niva::lattice::LatticeField;
use rust_flpcp::{Circuit, Flp, NormBound, Range};

const LENS: [usize; 4] = [10, 25, 50, 100];

fn lattice_bytes(elements: usize) -> f64 {
    let bits = Field128::MODULUS_BIT_SIZE + <Field128 as LatticeField>::Headroom::MODULUS_BIT_SIZE;
    let elements = u32::try_from(elements).expect("sizes fit in u32");
    f64::from(elements) * f64::from(bits) / 8.0
}

fn row<C: Circuit<Field128>>(rule: &str, len: usize, circuit: C) {
    let flp = Flp::<Field128, C>::new(circuit).expect("benchmark parameters are valid");
    let ring = Field128::RING_DIMENSION;
    let vector_len = flp.vector_len();
    println!(
        "| {rule} | {len} | {vector_len} | {} | {} | {} | {:.0} KB | {:.0} KB | {:.1} MB |",
        vector_len + 1,
        len + 1,
        flp.query_count(),
        lattice_bytes(ring + vector_len) / 1e3,
        lattice_bytes(ring + len) / 1e3,
        lattice_bytes((vector_len + 1) * ring) / 1e6,
    );
}

fn main() {
    println!(
        "| rule | len | vector_len | ciphertext forms | kept after validation | queries | lattice ciphertext | lattice kept | lattice public key |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    for len in LENS {
        row("binary", len, Range::binary(len));
    }
    for len in LENS {
        let circuit = NormBound {
            len,
            input_bits: 10,
            norm_bits: 20,
            square_chunk: None,
        };
        row("norm_bound", len, circuit);
    }
}
