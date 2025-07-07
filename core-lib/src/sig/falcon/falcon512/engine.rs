use rand::TryRngCore;
use secrecy::{ExposeSecret, SecretBox};
use std::ffi::c_void;
use std::mem::MaybeUninit;
use zeroize::Zeroize; 
use libc::c_int;     
use crate::sig::falcon::bindings::shake256_context;

use crate::sig::falcon::bindings::*; 
use crate::sig::falcon::errors::FalconErrors;
use crate::sig::falcon::falcon512::constants::*;
use crate::sig::falcon::falcon512::types::*; 
use crate::sig::traits::SignatureEngine;

const FALCON_SEED_LENGTH: usize = 48; 

fn initialize_falcon_rng(rng_state_uninit: &mut MaybeUninit<shake256_context>) -> Result<(), FalconErrors> {
    let mut seed = [0u8; FALCON_SEED_LENGTH];

    rand::rng().try_fill_bytes(&mut seed).map_err(|e| {
        eprintln!("FATAL: System RNG failed: {}", e);
        FalconErrors::RngInitializationFailed 
    })?;

    unsafe {
        shake256_init_prng_from_seed(
            rng_state_uninit.as_mut_ptr(),
            seed.as_ptr() as *const c_void,
            seed.len()
        ); 
    }

    seed.zeroize();
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Falcon512Engine;

impl SignatureEngine for Falcon512Engine {
    type PublicKey = Falcon512PublicKey;
    type SecretKey = Falcon512SecretKey;
    type Signature = Falcon512Signature;
    type Error = FalconErrors;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let mut pk_buf = [0u8; FALCON_PUBLIC];
        let mut sk_buf = [0u8; FALCON_SECRET];
        let mut tmp = vec![0u8; FALCON_TMPSIZE_KEYGEN]; 
        let mut rng_state = MaybeUninit::<shake256_context>::uninit();

        initialize_falcon_rng(&mut rng_state)?; 

        let keygen_result: c_int = unsafe {
            falcon_keygen_make(
                rng_state.as_mut_ptr(), 
                FALCON_LOGN as u32,
                sk_buf.as_mut_ptr() as *mut c_void, sk_buf.len(),
                pk_buf.as_mut_ptr() as *mut c_void, pk_buf.len(),
                tmp.as_mut_ptr() as *mut c_void, tmp.len(),
            )
        };
        drop(tmp); 

        if keygen_result != 0 {
            return Err(FalconErrors::KeyGenerationFailed);
        }

        Ok((PublicKey(pk_buf), SecretKey(SecretBox::new(Box::from(sk_buf)))))
    }

    fn sign(msg: &[u8], sk: &Self::SecretKey) -> Result<Self::Signature, Self::Error> {
        let sk_bytes = sk.0.expose_secret(); 
        let mut sig_buf = [0u8; FALCON_SIGNATURE];
        let mut siglen: usize = FALCON_SIGNATURE;
        let mut tmp = vec![0u8; FALCON_TMPSIZE_SIGNDYN];
        let mut rng_state = MaybeUninit::<shake256_context>::uninit();

        initialize_falcon_rng(&mut rng_state)?;

        let sign_result: c_int = unsafe {
            falcon_sign_dyn(
                rng_state.as_mut_ptr(), 
                sig_buf.as_mut_ptr() as *mut _, 
                &mut siglen,
                FALCON_SIG_COMPRESSED,
                sk_bytes.as_ptr() as *const c_void, sk_bytes.len(), 
                msg.as_ptr() as *const c_void, msg.len(),         
                tmp.as_mut_ptr() as *mut c_void, tmp.len(),
            )
        };

        drop(tmp);

        if sign_result != 0 {
            return Err(FalconErrors::SigningFailed);
        }
        
        // Truncate signature to actual length
        let mut actual_sig = [0u8; FALCON_SIGNATURE];
        actual_sig[..siglen].copy_from_slice(&sig_buf[..siglen]);
        if siglen < FALCON_SIGNATURE {
            // Zero out unused bytes
            actual_sig[siglen..].fill(0);
        }
        Ok(Signature(actual_sig))
    }

    fn verify(msg: &[u8], sig: &Self::Signature, pk: &Self::PublicKey) -> bool {
        let sig_bytes = &sig.0;
        let pk_bytes = &pk.0;
        
        // Use fixed signature length to prevent timing attacks
        // Variable-time signature length detection removed for security
        let actual_sig_len = sig_bytes.len();
        
        let mut tmp = vec![0u8; FALCON_TMPSIZE_VERIFY];

        let verify_result: c_int = unsafe {
            falcon_verify(
                sig_bytes.as_ptr() as *const c_void, actual_sig_len, FALCON_SIG_COMPRESSED,
                pk_bytes.as_ptr() as *const c_void, pk_bytes.len(),
                msg.as_ptr() as *const c_void, msg.len(),
                tmp.as_mut_ptr() as *mut c_void, tmp.len(),
            )
        };
        verify_result == 0
    }
}