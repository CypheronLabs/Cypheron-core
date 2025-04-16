use crate::sig::falcon::bindings::*;

pub const SIG_COMPRESSED: i32 = FALCON_SIG_COMPRESSED;
pub const SIG_PADDED: i32 = FALCON_SIG_PADDED;
pub const SIG_CT: i32 = FALCON_SIG_CT;

pub const fn logn_from_bit_level(bits: usize) -> u32 {
    match bits {
        512 => 9,
        1024 => 10,
        _ => panic!("Unsupported Falcon variant: {}", bits),
    }
}
