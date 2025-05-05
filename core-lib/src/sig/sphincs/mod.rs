pub mod shake_128f;
pub mod sha2_256s;
pub mod haraka_192f;
pub mod common;
mod errors;

pub use crate::sig::falcon::FalconVariant::Falcon512;
pub use crate::sig::falcon::FalconVariant::Falcon1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalconVariant {
    Falcon512,
    Falcon1024,
}