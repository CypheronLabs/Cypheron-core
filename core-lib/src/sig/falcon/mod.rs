mod bindings;
pub mod common;
mod errors;
pub mod falcon1024;
pub mod falcon512;

pub use crate::sig::falcon::FalconVariant::Falcon1024;
pub use crate::sig::falcon::FalconVariant::Falcon512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalconVariant {
    Falcon512,
    Falcon1024,
}
