pub mod falcon512;
pub mod falcon1024;
pub mod common;
mod errors;
mod bindings;

pub use crate::sig::falcon::FalconVariant::Falcon512;
pub use crate::sig::falcon::FalconVariant::Falcon1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalconVariant {
    Falcon512,
    Falcon1024,
}