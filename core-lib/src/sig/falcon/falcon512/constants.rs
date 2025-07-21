// core-lib/src/sig/falcon/falcon512/constants.rs

pub const FALCON_LOGN: usize = 9;

pub const FALCON_PUBLIC: usize = 897; // FALCON_PUBKEY_SIZE(9)
pub const FALCON_SECRET: usize = 1281; // FALCON_PRIVKEY_SIZE(9)
pub const FALCON_SIGNATURE: usize = 752; // FALCON_SIG_COMPRESSED_MAXSIZE(9)

// Signature type
pub const FALCON_SIG_COMPRESSED: i32 = 1;

// Temporary buffer sizes
pub const FALCON_TMPSIZE_KEYGEN: usize = 15879;
pub const FALCON_TMPSIZE_SIGNDYN: usize = 39943;
pub const FALCON_TMPSIZE_VERIFY: usize = 4097;
