use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CltError {
    DiscriminantTooSmall { bits: u32, minimum: u32 },
    DimensionMismatch { expected: usize, actual: usize },
    PrefixTooLong { len: usize, dimension: usize },
    DependentFunctionVectors,
    NotInSubgroup,
}

impl fmt::Display for CltError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DiscriminantTooSmall { bits, minimum } => write!(
                f,
                "discriminant of {bits} bits is below the minimum of {minimum} bits"
            ),
            Self::DimensionMismatch { expected, actual } => {
                write!(
                    f,
                    "vector has dimension {actual} but the key expects {expected}"
                )
            }
            Self::PrefixTooLong { len, dimension } => {
                write!(f, "prefix of {len} exceeds the dimension {dimension}")
            }
            Self::DependentFunctionVectors => {
                f.write_str("function vectors are linearly dependent over the field")
            }
            Self::NotInSubgroup => {
                f.write_str("ciphertext does not decrypt into the message subgroup")
            }
        }
    }
}

impl std::error::Error for CltError {}
