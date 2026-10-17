use rust_flpcp::FlpError;
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LatticeError {
    RingDimension { dimension: usize },
    DimensionTooLarge { dimension: usize, maximum: usize },
    DimensionMismatch { expected: usize, actual: usize },
    PrefixTooLong { len: usize, dimension: usize },
    DependentFunctionVectors,
    NoiseTooLarge,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PearError {
    Clt(CltError),
    Flp(FlpError),
    PayloadTooLong {
        payload_len: usize,
        input_len: usize,
    },
    CircuitMismatch,
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

impl fmt::Display for LatticeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RingDimension { dimension } => write!(
                f,
                "ring dimension {dimension} is not a supported power of two"
            ),
            Self::DimensionTooLarge { dimension, maximum } => {
                write!(f, "dimension {dimension} exceeds the maximum of {maximum}")
            }
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
            Self::NoiseTooLarge => f.write_str("ciphertext noise exceeds the decoding ceiling"),
        }
    }
}

impl std::error::Error for LatticeError {}

impl fmt::Display for PearError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clt(_) => f.write_str("functional encryption failed"),
            Self::Flp(_) => f.write_str("validity proof failed"),
            Self::PayloadTooLong {
                payload_len,
                input_len,
            } => write!(
                f,
                "payload of {payload_len} exceeds the circuit input length {input_len}"
            ),
            Self::CircuitMismatch => {
                f.write_str("circuit does not match the public or verification key")
            }
        }
    }
}

impl std::error::Error for PearError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clt(error) => Some(error),
            Self::Flp(error) => Some(error),
            Self::PayloadTooLong { .. } | Self::CircuitMismatch => None,
        }
    }
}

impl From<CltError> for PearError {
    fn from(error: CltError) -> Self {
        Self::Clt(error)
    }
}

impl From<FlpError> for PearError {
    fn from(error: FlpError) -> Self {
        Self::Flp(error)
    }
}
