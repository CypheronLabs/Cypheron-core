pub const fn logn_from_bit_level(bits: usize) -> u32 {
    match bits {
        512 => 9,
        1024 => 10,
        _ => panic!("Unsupported Falcon variant"),
    }
}
