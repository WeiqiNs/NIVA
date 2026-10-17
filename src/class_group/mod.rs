mod exp;

pub(crate) use exp::pow;

use dashu_int::ops::{DivRemEuclid, ExtendedGcd, RemEuclid};
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
        Self { discriminant }
    }

    pub(crate) fn discriminant(&self) -> &IBig {
        &self.discriminant
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
        self.reduced(left_part * right_part, b)
    }

    pub(crate) fn square(&self, form: &Form) -> Form {
        self.compose(form, form)
    }
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
    use super::{ClassGroup, Form, pow};
    use crate::number_theory::is_probable_prime;
    use crate::sampling::uniform_below;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::{RngCore, SeedableRng};
    use dashu_int::ops::{BitTest, Gcd, UnsignedAbs};
    use dashu_int::{IBig, UBig};
    use std::collections::BTreeSet;

    pub(crate) fn is_canonical(form: &Form, group: &ClassGroup) -> bool {
        let Form { a, b, c } = form;
        let ambiguous = b.unsigned_abs() == a.unsigned_abs() || a == c;
        b.sqr() - ((a * c) << 2) == *group.discriminant()
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

    pub(crate) fn large_group(rng: &mut StdRng) -> (ClassGroup, Form) {
        let mut candidate = uniform_below(&(UBig::ONE << 300), rng) | (UBig::ONE << 299);
        while !(candidate.bit(0) && candidate.bit(1) && is_probable_prime(&candidate, rng)) {
            candidate += UBig::ONE;
        }
        let group = ClassGroup::new(-IBig::from(candidate));
        let base = (2..).find_map(|prime| group.prime_form(prime)).unwrap();
        (group, base)
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
}
