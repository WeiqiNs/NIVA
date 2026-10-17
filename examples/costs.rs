use niva::Field128;
use rust_flpcp::{Circuit, Flp, NormBound, Range};

const LENS: [usize; 4] = [10, 25, 50, 100];

fn row<C: Circuit<Field128>>(rule: &str, len: usize, circuit: C) {
    let flp = Flp::<Field128, C>::new(circuit).expect("benchmark parameters are valid");
    println!(
        "| {rule} | {len} | {} | {} | {} | {} |",
        flp.vector_len(),
        flp.vector_len() + 1,
        len + 1,
        flp.query_count()
    );
}

fn main() {
    println!("| rule | len | vector_len | ciphertext forms | kept after validation | queries |");
    println!("|---|---|---|---|---|---|");
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
