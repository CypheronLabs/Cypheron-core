pub const ML_DSA_44_PUBLIC: usize = 1312;
pub const ML_DSA_44_SECRET: usize = 2528;
pub const ML_DSA_44_SIGNATURE: usize = 2420;

pub const ML_DSA_65_PUBLIC: usize = 1952;
pub const ML_DSA_65_SECRET: usize = 4032;
pub const ML_DSA_65_SIGNATURE: usize = 3309;

pub const ML_DSA_87_PUBLIC: usize = 2592;
pub const ML_DSA_87_SECRET: usize = 4896;
pub const ML_DSA_87_SIGNATURE: usize = 4627;

#[deprecated(since = "0.2.0", note = "Use ML_DSA_44_* constants for NIST FIPS 204 compliance")]
pub const DILITHIUM2_PUBLIC: usize = ML_DSA_44_PUBLIC;
#[deprecated(since = "0.2.0", note = "Use ML_DSA_44_* constants for NIST FIPS 204 compliance")]
pub const DILITHIUM2_SECRET: usize = ML_DSA_44_SECRET;
#[deprecated(since = "0.2.0", note = "Use ML_DSA_44_* constants for NIST FIPS 204 compliance")]
pub const DILITHIUM2_SIGNATURE: usize = ML_DSA_44_SIGNATURE;

#[deprecated(since = "0.2.0", note = "Use ML_DSA_65_* constants for NIST FIPS 204 compliance")]
pub const DILITHIUM3_PUBLIC: usize = ML_DSA_65_PUBLIC;
#[deprecated(since = "0.2.0", note = "Use ML_DSA_65_* constants for NIST FIPS 204 compliance")]
pub const DILITHIUM3_SECRET: usize = ML_DSA_65_SECRET;
#[deprecated(since = "0.2.0", note = "Use ML_DSA_65_* constants for NIST FIPS 204 compliance")]
pub const DILITHIUM3_SIGNATURE: usize = ML_DSA_65_SIGNATURE;

#[deprecated(since = "0.2.0", note = "Use ML_DSA_87_* constants for NIST FIPS 204 compliance")]
pub const DILITHIUM5_PUBLIC: usize = ML_DSA_87_PUBLIC;
#[deprecated(since = "0.2.0", note = "Use ML_DSA_87_* constants for NIST FIPS 204 compliance")]
pub const DILITHIUM5_SECRET: usize = ML_DSA_87_SECRET;
#[deprecated(since = "0.2.0", note = "Use ML_DSA_87_* constants for NIST FIPS 204 compliance")]
pub const DILITHIUM5_SIGNATURE: usize = ML_DSA_87_SIGNATURE;
