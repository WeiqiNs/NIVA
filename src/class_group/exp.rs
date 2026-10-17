use super::{ClassGroup, Form};
use ark_std::cfg_chunks;
use dashu_int::IBig;
use dashu_int::ops::{BitTest, UnsignedAbs};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

const WNAF_WINDOW: u32 = 5;
const FIXED_BASE_WINDOW: u32 = 6;

#[derive(Clone, Debug)]
pub(crate) struct FixedBase {
    table: Vec<Form>,
    beyond: Form,
}

fn signed_digits(exponent: &IBig, window: u32) -> Vec<i32> {
    let magnitude = exponent.unsigned_abs();
    let width = window as usize;
    let half = 1 << (window - 1);
    let mut digits = Vec::new();
    let mut carry = 0;
    let mut position = 0;
    while position < magnitude.bit_len() || carry != 0 {
        let chunk = (0..width)
            .filter(|&offset| magnitude.bit(position + offset))
            .fold(carry, |chunk, offset| chunk + (1 << offset));
        carry = i32::from(chunk >= half);
        digits.push(chunk - (carry << window));
        position += width;
    }
    if *exponent < IBig::ZERO {
        for digit in &mut digits {
            *digit = -*digit;
        }
    }
    digits
}

fn signed_term(form: &Form, digit: i32) -> Form {
    if digit < 0 {
        form.inverse()
    } else {
        form.clone()
    }
}

fn accumulate(group: &ClassGroup, total: Option<Form>, term: &Form) -> Form {
    match total {
        Some(total) => group.compose(&total, term),
        None => term.clone(),
    }
}

fn bucket_product<'a>(
    group: &ClassGroup,
    terms: impl Iterator<Item = (&'a Form, i32)>,
    window: u32,
) -> Option<Form> {
    let mut buckets: Vec<Option<Form>> = vec![None; 1 << (window - 1)];
    for (form, digit) in terms.filter(|&(_, digit)| digit != 0) {
        let slot = &mut buckets[digit.unsigned_abs() as usize - 1];
        *slot = Some(accumulate(group, slot.take(), &signed_term(form, digit)));
    }
    let mut running = None;
    let mut total = None;
    for bucket in buckets.into_iter().rev() {
        if let Some(bucket) = bucket {
            running = Some(accumulate(group, running, &bucket));
        }
        if let Some(running) = &running {
            total = Some(accumulate(group, total, running));
        }
    }
    total
}

fn square_times(group: &ClassGroup, form: Form, times: u32) -> Form {
    (0..times).fold(form, |form, _| group.square(&form))
}

pub(crate) fn pow(group: &ClassGroup, base: &Form, exponent: &IBig) -> Form {
    let digits = signed_digits(exponent, WNAF_WINDOW);
    let largest = digits
        .iter()
        .map(|digit| digit.unsigned_abs())
        .max()
        .unwrap_or(0);
    let mut powers = vec![base.clone()];
    while powers.len() < largest as usize {
        let next = group.compose(&powers[powers.len() - 1], base);
        powers.push(next);
    }
    let mut result: Option<Form> = None;
    for &digit in digits.iter().rev() {
        result = result.map(|form| square_times(group, form, WNAF_WINDOW));
        if digit != 0 {
            let term = signed_term(&powers[digit.unsigned_abs() as usize - 1], digit);
            result = Some(accumulate(group, result, &term));
        }
    }
    result.unwrap_or_else(|| group.identity())
}

impl FixedBase {
    pub(crate) fn new(group: &ClassGroup, base: Form, max_bits: usize) -> Self {
        let len = max_bits.div_ceil(FIXED_BASE_WINDOW as usize);
        let mut table = Vec::with_capacity(len);
        let mut power = base;
        for _ in 0..len {
            let next = square_times(group, power.clone(), FIXED_BASE_WINDOW);
            table.push(power);
            power = next;
        }
        Self {
            table,
            beyond: power,
        }
    }

    pub(crate) fn pow(&self, group: &ClassGroup, exponent: &IBig) -> Form {
        let digits = signed_digits(exponent, FIXED_BASE_WINDOW);
        let (low, high) = digits.split_at(digits.len().min(self.table.len()));
        let terms = self.table.iter().zip(low.iter().copied());
        let low_product = bucket_product(group, terms, FIXED_BASE_WINDOW);
        let high_exponent = high.iter().rev().fold(IBig::ZERO, |value, &digit| {
            (value << FIXED_BASE_WINDOW as usize) + digit
        });
        if high_exponent.is_zero() {
            return low_product.unwrap_or_else(|| group.identity());
        }
        let high_product = pow(group, &self.beyond, &high_exponent);
        accumulate(group, low_product, &high_product)
    }
}

fn pippenger(group: &ClassGroup, bases: &[Form], exponents: &[IBig]) -> Option<Form> {
    let window = bases.len().bit_width().saturating_sub(3).clamp(2, 16);
    let digits: Vec<Vec<i32>> = exponents
        .iter()
        .map(|exponent| signed_digits(exponent, window))
        .collect();
    let len = digits.iter().map(Vec::len).max().unwrap_or(0);
    let mut result: Option<Form> = None;
    for position in (0..len).rev() {
        result = result.map(|form| square_times(group, form, window));
        let column = digits
            .iter()
            .map(|digits| digits.get(position).copied().unwrap_or(0));
        if let Some(column) = bucket_product(group, bases.iter().zip(column), window) {
            result = Some(accumulate(group, result, &column));
        }
    }
    result
}

#[cfg(feature = "parallel")]
fn thread_count() -> usize {
    rayon::current_num_threads()
}

#[cfg(not(feature = "parallel"))]
fn thread_count() -> usize {
    1
}

pub(crate) fn multi_exp(group: &ClassGroup, bases: &[Form], exponents: &[IBig]) -> Form {
    let chunk = bases.len().div_ceil(thread_count()).max(1);
    let partials: Vec<Form> = cfg_chunks!(bases, chunk)
        .zip(cfg_chunks!(exponents, chunk))
        .filter_map(|(bases, exponents)| pippenger(group, bases, exponents))
        .collect();
    partials
        .into_iter()
        .reduce(|left, right| group.compose(&left, &right))
        .unwrap_or_else(|| group.identity())
}

#[cfg(test)]
mod tests {
    use super::{FixedBase, multi_exp, pow};
    use crate::class_group::tests::{large_group, rng, signed_below};
    use crate::class_group::{ClassGroup, Form};
    use dashu_int::ops::{BitTest, UnsignedAbs};
    use dashu_int::{IBig, UBig};

    fn pow_reference(group: &ClassGroup, base: &Form, exponent: &IBig) -> Form {
        let magnitude = exponent.unsigned_abs();
        let mut result = group.identity();
        for index in (0..magnitude.bit_len()).rev() {
            result = group.compose(&result, &result);
            if magnitude.bit(index) {
                result = group.compose(&result, base);
            }
        }
        if *exponent < IBig::ZERO {
            result.inverse()
        } else {
            result
        }
    }

    #[test]
    fn fast_exponentiation_matches_reference() {
        let mut rng = rng();
        let (group, base) = large_group(&mut rng);
        let word = IBig::from(UBig::from(u64::MAX));
        let exponents = [
            IBig::ZERO,
            IBig::ONE,
            -IBig::ONE,
            word.clone(),
            -word,
            signed_below(400, &mut rng),
        ];
        for exponent in &exponents {
            assert_eq!(
                pow(&group, &base, exponent),
                pow_reference(&group, &base, exponent),
                "{exponent}"
            );
        }

        for max_bits in [8, 400] {
            let fixed = FixedBase::new(&group, base.clone(), max_bits);
            for exponent in exponents
                .iter()
                .cloned()
                .chain([signed_below(64, &mut rng)])
            {
                assert_eq!(
                    fixed.pow(&group, &exponent),
                    pow_reference(&group, &base, &exponent),
                    "{max_bits} {exponent}"
                );
            }
        }

        for count in [0, 1, 2, 17, 300] {
            let bases: Vec<Form> = (0..count)
                .map(|_| pow(&group, &base, &signed_below(64, &mut rng)))
                .collect();
            let exponents: Vec<IBig> = (0..count)
                .map(|index| {
                    if index % 5 == 0 {
                        IBig::ZERO
                    } else {
                        signed_below(64, &mut rng)
                    }
                })
                .collect();
            let expected =
                bases
                    .iter()
                    .zip(&exponents)
                    .fold(group.identity(), |product, (base, exponent)| {
                        group.compose(&product, &pow_reference(&group, base, exponent))
                    });
            assert_eq!(multi_exp(&group, &bases, &exponents), expected, "{count}");
        }
    }
}
