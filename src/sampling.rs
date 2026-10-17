use ark_std::rand::{CryptoRng, RngCore};
use dashu_int::ops::{BitTest, DivRem, SquareRoot, UnsignedAbs};
use dashu_int::{IBig, UBig};

pub(crate) const NOISE_ETA: u32 = 21;

#[derive(Clone, Debug)]
pub(crate) struct DiscreteGaussian {
    variance: UBig,
    scale: UBig,
}

pub(crate) fn uniform_below(bound: &UBig, rng: &mut (impl CryptoRng + RngCore)) -> UBig {
    let bits = (bound - UBig::ONE).bit_len();
    let mut bytes = vec![0u8; bits.div_ceil(8)];
    loop {
        rng.fill_bytes(&mut bytes);
        if let Some(top) = bytes.last_mut() {
            *top &= u8::MAX >> ((8 - bits % 8) % 8);
        }
        let candidate = UBig::from_le_bytes(&bytes);
        if candidate < *bound {
            return candidate;
        }
    }
}

#[allow(dead_code)]
pub(crate) fn centered_binomial(rng: &mut (impl CryptoRng + RngCore)) -> i64 {
    let mask = (1u64 << NOISE_ETA) - 1;
    let bits = rng.next_u64();
    i64::from((bits & mask).count_ones()) - i64::from(((bits >> NOISE_ETA) & mask).count_ones())
}

fn bernoulli_exp_neg_at_most_one(
    numerator: &UBig,
    denominator: &UBig,
    rng: &mut (impl CryptoRng + RngCore),
) -> bool {
    let mut count = 1u64;
    while uniform_below(&(denominator * count), rng) < *numerator {
        count += 1;
    }
    count % 2 == 1
}

fn bernoulli_exp_neg(
    numerator: &UBig,
    denominator: &UBig,
    rng: &mut (impl CryptoRng + RngCore),
) -> bool {
    let (mut whole, fraction) = numerator.div_rem(denominator);
    while !whole.is_zero() {
        if !bernoulli_exp_neg_at_most_one(&UBig::ONE, &UBig::ONE, rng) {
            return false;
        }
        whole -= UBig::ONE;
    }
    bernoulli_exp_neg_at_most_one(&fraction, denominator, rng)
}

fn discrete_laplace(scale: &UBig, rng: &mut (impl CryptoRng + RngCore)) -> IBig {
    loop {
        let offset = uniform_below(scale, rng);
        if !bernoulli_exp_neg(&offset, scale, rng) {
            continue;
        }
        let mut periods = UBig::ZERO;
        while bernoulli_exp_neg(&UBig::ONE, &UBig::ONE, rng) {
            periods += UBig::ONE;
        }
        let magnitude = offset + scale * periods;
        let negative = rng.next_u32() & 1 == 1;
        if negative && magnitude.is_zero() {
            continue;
        }
        let value = IBig::from(magnitude);
        return if negative { -value } else { value };
    }
}

impl DiscreteGaussian {
    pub(crate) fn new(variance: UBig) -> Self {
        let scale = variance.sqrt() + UBig::ONE;
        Self { variance, scale }
    }

    pub(crate) fn sample(&self, rng: &mut (impl CryptoRng + RngCore)) -> IBig {
        let denominator = UBig::from(2u8) * &self.variance * self.scale.sqr();
        loop {
            let candidate = discrete_laplace(&self.scale, rng);
            let distance = IBig::from((&candidate).unsigned_abs() * &self.scale)
                - IBig::from(self.variance.clone());
            if bernoulli_exp_neg(&distance.unsigned_abs().sqr(), &denominator, rng) {
                return candidate;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DiscreteGaussian, NOISE_ETA, bernoulli_exp_neg, centered_binomial, uniform_below};
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;
    use dashu_int::UBig;
    use std::collections::BTreeSet;
    use std::f64::consts::TAU;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(2)
    }

    #[test]
    fn uniform_below_stays_in_range_and_covers_it() {
        let mut rng = rng();
        let bounds = [
            UBig::ONE,
            UBig::from(2u8),
            UBig::from(255u8),
            UBig::from(256u16),
            (UBig::ONE << 130) + UBig::ONE,
        ];
        for bound in bounds {
            for _ in 0..200 {
                assert!(uniform_below(&bound, &mut rng) < bound, "{bound}");
            }
        }
        let three = UBig::from(3u8);
        let seen: BTreeSet<UBig> = (0..200).map(|_| uniform_below(&three, &mut rng)).collect();
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn bernoulli_exp_neg_frequencies() {
        const DRAWS: u16 = 20_000;
        let mut rng = rng();
        for (numerator, denominator) in [(0u8, 1u8), (1, 2), (1, 1), (5, 2)] {
            let expected = (-f64::from(numerator) / f64::from(denominator)).exp();
            let (numerator, denominator) = (UBig::from(numerator), UBig::from(denominator));
            let hits = (0..DRAWS)
                .filter(|_| bernoulli_exp_neg(&numerator, &denominator, &mut rng))
                .count();
            let frequency = f64::from(u16::try_from(hits).unwrap()) / f64::from(DRAWS);
            assert!(
                (frequency - expected).abs() < 0.02,
                "{expected}: {frequency}"
            );
        }
    }

    #[test]
    fn discrete_gaussian_matches_its_moments() {
        const SAMPLES: u16 = 20_000;
        let mut rng = rng();
        let gaussian = DiscreteGaussian::new(UBig::from(100u8));
        let samples: Vec<i32> = (0..SAMPLES)
            .map(|_| i32::try_from(&gaussian.sample(&mut rng)).unwrap())
            .collect();
        let count = f64::from(SAMPLES);
        let mean = samples.iter().copied().map(f64::from).sum::<f64>() / count;
        let variance = samples
            .iter()
            .map(|&x| (f64::from(x) - mean).powi(2))
            .sum::<f64>()
            / count;
        assert!(mean.abs() < 0.5, "{mean}");
        assert!((95.0..=105.0).contains(&variance), "{variance}");
        assert!(samples.iter().all(|x| x.abs() < 100));

        let zeros = samples.iter().filter(|&&x| x == 0).count();
        let zero_mass = f64::from(u16::try_from(zeros).unwrap()) / count;
        let expected = (10.0 * TAU.sqrt()).recip();
        assert!((zero_mass - expected).abs() < 0.01, "{zero_mass}");
    }

    #[test]
    fn centered_binomial_matches_its_moments() {
        const SAMPLES: u16 = 20_000;
        let mut rng = rng();
        let samples: Vec<i64> = (0..SAMPLES).map(|_| centered_binomial(&mut rng)).collect();
        let count = f64::from(SAMPLES);
        let values: Vec<f64> = samples
            .iter()
            .map(|&x| f64::from(i32::try_from(x).unwrap()))
            .collect();
        let mean = values.iter().sum::<f64>() / count;
        let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / count;
        assert!(mean.abs() < 0.1, "{mean}");
        assert!((10.0..=11.0).contains(&variance), "{variance}");
        let eta = i64::from(NOISE_ETA);
        assert!(samples.iter().all(|x| (-eta..=eta).contains(x)));
    }
}
