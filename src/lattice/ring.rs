use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

#[derive(Debug)]
pub(crate) struct Ring<K: FftField> {
    domain: Radix2EvaluationDomain<K>,
}

impl<K: FftField> Ring<K> {
    pub(crate) fn new(dimension: usize) -> Option<Self> {
        let twist = K::get_root_of_unity(2 * u64::try_from(dimension).ok()?)?;
        Some(Self {
            domain: Radix2EvaluationDomain::new_coset(dimension, twist)?,
        })
    }

    pub(crate) fn dimension(&self) -> usize {
        self.domain.size()
    }

    pub(crate) fn forward(&self, coefficients: &[i64]) -> Vec<K> {
        let mut values: Vec<K> = coefficients.iter().map(|&value| K::from(value)).collect();
        self.domain.fft_in_place(&mut values);
        values
    }

    pub(crate) fn constant_term(&self, left: &[K], right: &[K]) -> K {
        left.iter().zip(right).map(|(&a, &b)| a * b).sum::<K>() * self.domain.size_inv
    }
}

#[cfg(test)]
mod tests {
    use super::Ring;
    use crate::Field128;
    use crate::lattice::Headroom150;
    use ark_ff::FftField;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::{Rng, SeedableRng};

    fn schoolbook_constant_term(left: &[i64], right: &[i64]) -> i128 {
        let dimension = left.len();
        let wrapped: i128 = (1..dimension)
            .map(|k| i128::from(left[k]) * i128::from(right[dimension - k]))
            .sum();
        i128::from(left[0]) * i128::from(right[0]) - wrapped
    }

    fn assert_constant_terms<K: FftField>(dimension: usize, rng: &mut StdRng) {
        let negacyclic = Ring::<K>::new(dimension).unwrap();
        assert_eq!(negacyclic.dimension(), dimension);
        let mut polynomial = || -> Vec<i64> {
            (0..dimension)
                .map(|_| rng.gen_range(-(1 << 20)..=1 << 20))
                .collect()
        };
        for _ in 0..4 {
            let (left, right) = (polynomial(), polynomial());
            assert_eq!(
                negacyclic.constant_term(&negacyclic.forward(&left), &negacyclic.forward(&right)),
                K::from(schoolbook_constant_term(&left, &right)),
                "{dimension}"
            );
        }
    }

    #[test]
    fn negacyclic_constant_term_matches_schoolbook() {
        let mut rng = StdRng::seed_from_u64(3);
        for dimension in [2, 16, 1024] {
            assert_constant_terms::<Field128>(dimension, &mut rng);
            assert_constant_terms::<Headroom150>(dimension, &mut rng);
        }
    }
}
