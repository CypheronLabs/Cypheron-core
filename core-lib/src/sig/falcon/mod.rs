
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/falcon_bindings.rs"));
}
pub mod falcon512;
pub mod falcon1024;
pub mod common;

pub use falcon512::engine::Falcon512;
pub use falcon1024::engine::Falcon1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalconVariant {
    Falcon512,
    Falcon1024,
}