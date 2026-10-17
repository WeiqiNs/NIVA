use super::{ClassGroup, Form};
use dashu_int::IBig;
use dashu_int::ops::{BitTest, UnsignedAbs};

pub(crate) fn pow(group: &ClassGroup, base: &Form, exponent: &IBig) -> Form {
    let magnitude = exponent.unsigned_abs();
    let mut result = group.identity();
    for index in (0..magnitude.bit_len()).rev() {
        result = group.square(&result);
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
