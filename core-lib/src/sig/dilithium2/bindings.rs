#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/dilithium_2_bindings.rs"));
}
pub use bindings::*;
