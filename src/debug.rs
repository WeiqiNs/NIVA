use std::fmt;

pub(crate) fn redacted(f: &mut fmt::Formatter<'_>, name: &str, dimension: usize) -> fmt::Result {
    f.debug_struct(name)
        .field("dimension", &dimension)
        .finish_non_exhaustive()
}
