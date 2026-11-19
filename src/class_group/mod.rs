mod exp;

pub(crate) use exp::{FixedBase, multi_exp, pow};

use dashu_int::ops::{
    BitTest, DivRem, DivRemEuclid, ExtendedGcd, RemEuclid, SquareRoot, UnsignedAbs,
};
use dashu_int::{IBig, UBig};
use std::mem;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Form {
    pub(crate) a: IBig,
    pub(crate) b: IBig,
    pub(crate) c: IBig,
}

#[derive(Clone, Debug)]
pub(crate) struct ClassGroup {
    discriminant: IBig,
    nucomp_bound: IBig,
}

struct PartialComposition<'a> {
    right: &'a Form,
    common: IBig,
    left_part: IBig,
    right_part: IBig,
    shift: IBig,
}

impl Form {
    pub(crate) fn is_identity(&self) -> bool {
        self.a.is_one()
    }

    pub(crate) fn inverse(&self) -> Self {
        if self.b == self.a || self.a == self.c {
            return self.clone();
        }
        Self {
            a: self.a.clone(),
            b: -&self.b,
            c: self.c.clone(),
        }
    }
}

impl ClassGroup {
    pub(crate) fn new(discriminant: IBig) -> Self {
        let nucomp_bound = IBig::from((&discriminant).unsigned_abs().sqrt().sqrt());
        Self {
            discriminant,
            nucomp_bound,
        }
    }

    pub(crate) fn identity(&self) -> Form {
        Form {
            a: IBig::ONE,
            b: IBig::ONE,
            c: (IBig::ONE - &self.discriminant) >> 2,
        }
    }

    pub(crate) fn reduced(&self, a: IBig, b: IBig) -> Form {
        let c = (b.sqr() - &self.discriminant) / (&a << 2);
        reduce(Form { a, b, c })
    }

    pub(crate) fn prime_form(&self, prime: u64) -> Option<Form> {
        let modulus = 4 * prime;
        let target = (&self.discriminant).rem_euclid(IBig::from(modulus));
        if (&target % prime) == 0 {
            return None;
        }
        let b = (0..2 * prime).find(|&b| target == UBig::from(b * b % modulus))?;
        Some(self.reduced(IBig::from(prime), IBig::from(b)))
    }

    pub(crate) fn compose(&self, left: &Form, right: &Form) -> Form {
        let (left, right) = if left.a < right.a {
            (right, left)
        } else {
            (left, right)
        };
        let half_sum = (&left.b + &right.b) >> 1;
        let half_difference = &right.b - &half_sum;
        let (divisor, right_coeff, _) = (&right.a).gcd_ext(&left.a);
        let (common, sum_coeff, divisor_coeff) = (&half_sum).gcd_ext(&divisor);
        let common = IBig::from(common);
        let left_part = &left.a / &common;
        let shift = (-(right_coeff * divisor_coeff * half_difference) - sum_coeff * &right.c)
            .rem_euclid(&left_part);
        self.finish(PartialComposition {
            right,
            right_part: &right.a / &common,
            common,
            shift: IBig::from(shift),
            left_part,
        })
    }

    pub(crate) fn square(&self, form: &Form) -> Form {
        let (common, b_coeff, _) = (&form.b).gcd_ext(&form.a);
        let common = IBig::from(common);
        let part = &form.a / &common;
        let shift = (-(b_coeff * &form.c)).rem_euclid(&part);
        self.finish(PartialComposition {
            right: form,
            common,
            left_part: part.clone(),
            right_part: part,
            shift: IBig::from(shift),
        })
    }

    fn finish(&self, composition: PartialComposition<'_>) -> Form {
        let PartialComposition {
            right,
            common,
            left_part,
            right_part,
            shift,
        } = composition;
        let Euclid {
            far,
            far_coeff,
            near,
            near_coeff,
            odd,
        } = partial_euclid(left_part.clone(), shift, &self.nucomp_bound);

        let scaled_c = &common * &right.c;
        let norm = |value: &IBig, coeff: &IBig| {
            (&right_part * value.sqr() + &right.b * value * coeff + &scaled_c * coeff.sqr())
                / &left_part
        };
        let trace = ((&right_part * &far * &near + &scaled_c * &far_coeff * &near_coeff) << 1)
            + &right.b * (&far * &near_coeff + &near * &far_coeff);
        let b = trace / &left_part;
        reduce(Form {
            a: norm(&far, &far_coeff),
            b: if odd { -b } else { b },
            c: norm(&near, &near_coeff),
        })
    }
}

/// Bits of `far` read by one Lehmer chunk, so that every intermediate value
/// of the chunk fits comfortably in an `i128`.
const LEHMER_BITS: usize = 63;
/// A Lehmer chunk keeps every entry of its matrix below `2^LEHMER_COFACTOR_BITS`.
const LEHMER_COFACTOR_BITS: u32 = 31;

/// The state of NUCOMP's partial extended Euclid on `(far, near)`, with
/// `far_coeff` and `near_coeff` the cofactors of the initial `near` and `odd`
/// the parity of the number of division steps taken.
#[derive(Debug, PartialEq, Eq)]
struct Euclid {
    far: IBig,
    far_coeff: IBig,
    near: IBig,
    near_coeff: IBig,
    odd: bool,
}

impl Euclid {
    fn step(&mut self) {
        let (quotient, remainder) = (&self.far).div_rem(&self.near);
        let next_coeff = &self.far_coeff - &quotient * &self.near_coeff;
        self.far = mem::replace(&mut self.near, remainder);
        self.far_coeff = mem::replace(&mut self.near_coeff, next_coeff);
        self.odd = !self.odd;
    }

    /// Takes as many division steps as the top `LEHMER_BITS` of `far` and
    /// `near` determine (Knuth, TAOCP vol. 2, Algorithm 4.5.2L), then applies
    /// them to the full values at once. Each quotient taken is bracketed by two
    /// estimates that agree, so it equals the true quotient and the result is
    /// the state after that many single steps.
    fn lehmer_chunk(&mut self) {
        let shift = self.far.bit_len().saturating_sub(LEHMER_BITS);
        let top = |value: &IBig| i128::try_from(&(value >> shift)).expect("top bits fit in i128");
        let (mut far_top, mut near_top) = (top(&self.far), top(&self.near));
        // Rows of the chunk's matrix: far = far_row · (far, near) at the
        // start, and likewise for near. Knuth's (A, B) and (C, D).
        let (mut far_row, mut near_row) = ([1_i128, 0], [0_i128, 1]);
        let cap = 1_i128 << LEHMER_COFACTOR_BITS;
        let mut odd = false;
        while near_top + near_row[0] > 0 && near_top + near_row[1] > 0 {
            let quotient = (far_top + far_row[0]) / (near_top + near_row[0]);
            let next_row = [
                far_row[0] - quotient * near_row[0],
                far_row[1] - quotient * near_row[1],
            ];
            if quotient != (far_top + far_row[1]) / (near_top + near_row[1])
                || next_row.iter().any(|entry| entry.abs() >= cap)
            {
                break;
            }
            far_row = mem::replace(&mut near_row, next_row);
            (far_top, near_top) = (near_top, far_top - quotient * near_top);
            odd = !odd;
        }
        let apply = |row: [i128; 2], far: &IBig, near: &IBig| {
            far * IBig::from(row[0]) + near * IBig::from(row[1])
        };
        (self.far, self.near) = (
            apply(far_row, &self.far, &self.near),
            apply(near_row, &self.far, &self.near),
        );
        (self.far_coeff, self.near_coeff) = (
            apply(far_row, &self.far_coeff, &self.near_coeff),
            apply(near_row, &self.far_coeff, &self.near_coeff),
        );
        self.odd ^= odd;
    }
}

/// Runs the extended Euclid on `(far, near)` until `near <= bound`, with the
/// same result as single division steps.
///
/// A Lehmer chunk whose matrix entries are below `M = 2^LEHMER_COFACTOR_BITS`
/// ends with `far_end > far_start / 2M`: the matrix is unimodular, so
/// `far_start = |D|·far_end + |B|·near_end` with `near_end < far_end`. Running
/// a chunk only while `far` has `LEHMER_COFACTOR_BITS + 3` more bits than
/// `bound` therefore keeps every remainder the chunk divides by above `bound`,
/// so no chunk steps past the point where the single-step loop stops.
fn partial_euclid(far: IBig, near: IBig, bound: &IBig) -> Euclid {
    let lehmer_bits = bound.bit_len() + LEHMER_COFACTOR_BITS as usize + 3;
    let mut state = Euclid {
        far,
        far_coeff: IBig::ZERO,
        near,
        near_coeff: IBig::ONE,
        odd: false,
    };
    while state.near > *bound {
        if state.far.bit_len() >= lehmer_bits {
            state.lehmer_chunk();
        }
        // A chunk may make no progress (its first quotient is ambiguous) or
        // may end exactly where the loop stops, so the single step is guarded.
        if state.near > *bound {
            state.step();
        }
    }
    state
}

fn reduce(form: Form) -> Form {
    let Form {
        mut a,
        mut b,
        mut c,
    } = form;
    loop {
        if b <= -&a || b > a {
            let two_a = &a << 1;
            let (mut quotient, remainder) = (&b).div_rem_euclid(&two_a);
            let mut remainder = IBig::from(remainder);
            if remainder > a {
                remainder -= &two_a;
                quotient += IBig::ONE;
            }
            c -= ((&b + &remainder) >> 1) * quotient;
            b = remainder;
        }
        if a > c {
            b = -b;
            mem::swap(&mut a, &mut c);
            continue;
        }
        if a == c && b < IBig::ZERO {
            b = -b;
        }
        return Form { a, b, c };
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{ClassGroup, Euclid, Form, partial_euclid, pow};
    use crate::number_theory::is_probable_prime;
    use crate::sampling::uniform_below;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::{RngCore, SeedableRng};
    use dashu_int::ops::{BitTest, ExtendedGcd, Gcd, RemEuclid, UnsignedAbs};
    use dashu_int::{IBig, UBig};
    use std::collections::BTreeSet;

    pub(crate) fn is_canonical(form: &Form, group: &ClassGroup) -> bool {
        let Form { a, b, c } = form;
        let ambiguous = b.unsigned_abs() == a.unsigned_abs() || a == c;
        b.sqr() - ((a * c) << 2) == group.discriminant
            && *a > IBig::ZERO
            && b.unsigned_abs() <= a.unsigned_abs()
            && a <= c
            && (!ambiguous || *b >= IBig::ZERO)
    }

    fn is_primitive(a: i64, b: i64, c: i64) -> bool {
        a.unsigned_abs().gcd(b.unsigned_abs()).gcd(c.unsigned_abs()) == 1
    }

    fn form(a: i64, b: i64, c: i64) -> Form {
        Form {
            a: a.into(),
            b: b.into(),
            c: c.into(),
        }
    }

    pub(crate) fn reduced_forms(discriminant: i64) -> BTreeSet<(i64, i64, i64)> {
        let mut forms = BTreeSet::new();
        for a in 1..=(-discriminant / 3).isqrt() {
            for b in 1 - a..=a {
                let numerator = b * b - discriminant;
                let c = numerator / (4 * a);
                if numerator % (4 * a) == 0 && a <= c && !(a == c && b < 0) && is_primitive(a, b, c)
                {
                    forms.insert((a, b, c));
                }
            }
        }
        forms
    }

    fn as_tuple(form: &Form) -> (i64, i64, i64) {
        let part = |value: &IBig| i64::try_from(value).unwrap();
        (part(&form.a), part(&form.b), part(&form.c))
    }

    pub(crate) fn rng() -> StdRng {
        StdRng::seed_from_u64(5)
    }

    pub(crate) fn signed_below(bits: usize, rng: &mut StdRng) -> IBig {
        let magnitude = IBig::from(uniform_below(&(UBig::ONE << bits), rng));
        if rng.next_u32() & 1 == 1 {
            -magnitude
        } else {
            magnitude
        }
    }

    #[test]
    fn partial_euclid_matches_single_steps() {
        let mut rng = rng();
        let below =
            |bits: usize, rng: &mut StdRng| IBig::from(uniform_below(&(UBig::ONE << bits), rng));
        for bits in [8, 40, 64, 100, 300, 1040] {
            for bound_bits in [1, 16, bits / 4, bits / 2, bits - 1] {
                for _ in 0..25 {
                    let far = below(bits, &mut rng) + IBig::ONE;
                    let near = IBig::from(uniform_below(&(&far).unsigned_abs(), &mut rng));
                    let bound = below(bound_bits, &mut rng) + IBig::ONE;
                    let mut expected = Euclid {
                        far: far.clone(),
                        far_coeff: IBig::ZERO,
                        near: near.clone(),
                        near_coeff: IBig::ONE,
                        odd: false,
                    };
                    while expected.near > bound {
                        expected.step();
                    }
                    assert_eq!(
                        partial_euclid(far.clone(), near.clone(), &bound),
                        expected,
                        "{far} {near} {bound}"
                    );
                }
            }
        }
    }

    pub(crate) fn large_group(rng: &mut StdRng) -> (ClassGroup, Form) {
        let mut candidate = uniform_below(&(UBig::ONE << 300), rng) | (UBig::ONE << 299);
        while !(candidate.bit(0) && candidate.bit(1) && is_probable_prime(&candidate, rng)) {
            candidate += UBig::ONE;
        }
        let group = ClassGroup::new(-IBig::from(candidate));
        let base = (2..).find_map(|prime| group.prime_form(prime)).unwrap();
        (group, base)
    }

    fn compose_reference(group: &ClassGroup, left: &Form, right: &Form) -> Form {
        let half_sum = (&left.b + &right.b) >> 1;
        let half_difference = &right.b - &half_sum;
        let (divisor, right_coeff, _) = (&right.a).gcd_ext(&left.a);
        let (common, sum_coeff, divisor_coeff) = (&half_sum).gcd_ext(&divisor);
        let common = IBig::from(common);
        let left_part = &left.a / &common;
        let right_part = &right.a / &common;
        let shift = (-(right_coeff * divisor_coeff * half_difference) - sum_coeff * &right.c)
            .rem_euclid(&left_part);
        let b = &right.b + ((&right_part * IBig::from(shift)) << 1);
        group.reduced(left_part * right_part, b)
    }

    #[test]
    fn reduction_yields_each_reduced_form_once() {
        for (discriminant, size) in [(-23, 3), (-35, 2), (-47, 5), (-71, 7), (-2875, 10)] {
            let group = ClassGroup::new(discriminant.into());
            let expected = reduced_forms(discriminant);
            assert_eq!(expected.len(), size, "{discriminant}");

            let mut seen = BTreeSet::new();
            for a in 1..=2 * (-discriminant).isqrt() {
                for b in -(2 * a + 1)..=2 * a + 1 {
                    let numerator = b * b - discriminant;
                    if numerator % (4 * a) != 0 || !is_primitive(a, b, numerator / (4 * a)) {
                        continue;
                    }
                    let reduced = group.reduced(a.into(), b.into());
                    assert!(is_canonical(&reduced, &group), "{discriminant}: {a} {b}");
                    seen.insert(as_tuple(&reduced));
                }
            }
            assert_eq!(seen, expected, "{discriminant}");
        }
    }

    #[test]
    fn small_class_groups_satisfy_group_laws() {
        for discriminant in [-23, -35, -47, -71] {
            let group = ClassGroup::new(discriminant.into());
            let forms: Vec<Form> = reduced_forms(discriminant)
                .into_iter()
                .map(|(a, b, c)| form(a, b, c))
                .collect();
            let order = forms.len();
            let identity = group.identity();
            assert!(identity.is_identity() && forms.contains(&identity));
            for f in &forms {
                assert_eq!(group.compose(f, &identity), *f);
                assert!(is_canonical(&f.inverse(), &group));
                assert!(group.compose(f, &f.inverse()).is_identity());
                assert_eq!(group.square(f), group.compose(f, f));
                let mut power = f.clone();
                let mut steps = 1;
                while !power.is_identity() {
                    power = group.compose(&power, f);
                    steps += 1;
                }
                assert_eq!(steps, if f.is_identity() { 1 } else { order });
                for g in &forms {
                    let product = group.compose(f, g);
                    assert!(forms.contains(&product));
                    assert_eq!(product, group.compose(g, f));
                    for h in &forms {
                        assert_eq!(
                            group.compose(&product, h),
                            group.compose(f, &group.compose(g, h))
                        );
                    }
                }
            }
        }

        let group = ClassGroup::new((-2875).into());
        assert_eq!(group.prime_form(5), None);
        assert!(group.prime_form(7).is_some());
    }

    #[test]
    fn exponent_laws_hold_for_signed_exponents() {
        let mut rng = rng();
        let (group, base) = large_group(&mut rng);
        assert!(is_canonical(&base, &group));
        assert!(pow(&group, &base, &IBig::ZERO).is_identity());

        let random = signed_below(200, &mut rng);
        let pairs = [
            (IBig::ZERO, random.clone()),
            (IBig::ONE, -IBig::ONE),
            (random.clone(), -random),
            (signed_below(200, &mut rng), signed_below(200, &mut rng)),
        ];
        for (a, b) in pairs {
            let power_a = pow(&group, &base, &a);
            let power_b = pow(&group, &base, &b);
            let power_sum = pow(&group, &base, &(&a + &b));
            assert_eq!(group.compose(&power_a, &power_b), power_sum, "{a} {b}");
            assert_eq!(pow(&group, &power_a, &b), pow(&group, &base, &(&a * &b)));
            assert_eq!(pow(&group, &base, &-&a), power_a.inverse());
            for power in [&power_a, &power_b, &power_sum] {
                assert!(is_canonical(power, &group));
            }
        }
    }

    #[test]
    fn nucomp_matches_reference_composition() {
        let mut rng = rng();
        let (group, base) = large_group(&mut rng);
        for _ in 0..200 {
            let left = pow(&group, &base, &signed_below(64, &mut rng));
            let right = pow(&group, &base, &signed_below(64, &mut rng));
            let product = group.compose(&left, &right);
            assert_eq!(product, compose_reference(&group, &left, &right));
            assert_eq!(group.square(&left), compose_reference(&group, &left, &left));
            assert!(is_canonical(&product, &group));
        }
    }
}
