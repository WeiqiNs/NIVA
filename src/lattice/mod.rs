mod params;
#[allow(dead_code)]
mod ring;

pub use params::{Headroom150, Headroom150Config, LatticeField, Params};

pub const MAX_DIMENSION: usize = 8192;
