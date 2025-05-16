#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(non_upper_case_globals)]
pub mod robust_ffi {
    include!(concat!(env!("OUT_DIR"), "/sphincsplus_sphincs_shake_192f_robust_bindings.rs"));
}

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(non_upper_case_globals)]
pub mod simple_ffi {
    include!(concat!(env!("OUT_DIR"), "/sphincsplus_sphincs_shake_192f_simple_bindings.rs"));
}