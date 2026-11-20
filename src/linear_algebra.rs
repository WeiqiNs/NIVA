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

#[cfg(test)]
mod tests {
    use super::linearly_independent;
    use crate::Field128;
    use ark_ff::{AdditiveGroup, Field};

    #[test]
    fn rank_test_needs_no_pivot_in_the_first_row() {
        let (zero, one) = (Field128::ZERO, Field128::ONE);
        let vector = [one, Field128::from(5u8), zero];
        let doubled = vector.map(|value| value.double());
        let cases: [(&[&[Field128]], bool); 5] = [
            (
                &[&[zero, one, zero], &[one, zero, zero], &[zero, zero, one]],
                true,
            ),
            (&[&[zero, one, zero], &[zero, zero, one]], true),
            (&[&vector, &doubled], false),
            (&[&[zero, zero, zero]], false),
            (&[], true),
        ];
        for (vectors, expected) in cases {
            assert_eq!(linearly_independent(vectors), expected, "{vectors:?}");
        }
    }
}
