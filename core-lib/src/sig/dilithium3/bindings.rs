mod bindings {
    #[allow(non_camel_case_types)]
    #[allow(non_snake_case)]
    #[allow(non_upper_case_globals)]
    include!(concat!(env!("OUT_DIR"), "/dilithium_3_bindings.rs"));
}

use bindings::*;