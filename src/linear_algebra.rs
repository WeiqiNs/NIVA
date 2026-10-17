use ark_ff::Field;

pub(crate) fn linearly_independent<F: Field>(vectors: &[&[F]]) -> bool {
    let mut rows: Vec<Vec<F>> = vectors.iter().map(|vector| vector.to_vec()).collect();
    let columns = rows.first().map_or(0, Vec::len);
    let mut rank = 0;
    for column in 0..columns {
        let Some(offset) = rows[rank..].iter().position(|row| !row[column].is_zero()) else {
            continue;
        };
        rows.swap(rank, rank + offset);
        let (done, rest) = rows.split_at_mut(rank + 1);
        let pivot_row = &done[rank];
        for row in rest {
            let factor = row[column];
            for (entry, &pivot_entry) in row.iter_mut().zip(pivot_row) {
                *entry = *entry * pivot_row[column] - factor * pivot_entry;
            }
        }
        rank += 1;
    }
    rank == rows.len()
}
