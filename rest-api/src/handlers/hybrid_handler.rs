use crate::error::AppError;
use crate::models::hybrid::{HybridSignRequest, HybridSignResponse};
use crate::utils::encoding::{decode_base64_url, encode_base64_url};
use axum::{response::IntoResponse, Json};
use core_lib::sig::dilithium::common::ML_DSA_44_SECRET;
use core_lib::sig::dilithium::dilithium2::{types::SecretKey as Dilithium2SecretKey, Dilithium2};
use core_lib::sig::traits::SignatureEngine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use secrecy::SecretBox;
use serde_json::json;

pub async fn sign_hybrid_jwt(
    Json(payload): Json<HybridSignRequest>,
) -> Result<impl IntoResponse, AppError> {
    let header = json!({
        "alg": "ES256+Dilithium2",
        "typ": "JWT",
    });

    let payload_json = json!({
        "message": payload.message,
    });
    let header_base64 =
        encode_base64_url(&serde_json::to_vec(&header).map_err(|_| AppError::InvalidBase64)?);
    let payload_base64 =
        encode_base64_url(&serde_json::to_vec(&payload_json).map_err(|_| AppError::InvalidBase64)?);
    let signing_input = format!("{}.{}", header_base64, payload_base64);

    let es256_sk_bytes = decode_base64_url(&payload.es256)?;
    let es256_sk_array: [u8; 32] =
        es256_sk_bytes.try_into().map_err(|_| AppError::InvalidSecretKey)?;

    let es256_sk =
        SigningKey::from_bytes((&es256_sk_array).into()).map_err(|_| AppError::InvalidSecretKey)?;
    let es256_signature: Signature = es256_sk.sign(signing_input.as_bytes());
    let es256_signature_base64 = encode_base64_url(&es256_signature.to_der().as_bytes());

    let dilithium2_sk_bytes = decode_base64_url(&payload.dilithium2_sk)?;
    let arr: [u8; ML_DSA_44_SECRET] =
        dilithium2_sk_bytes.try_into().map_err(|_| AppError::InvalidSecretKey)?;
    let dilithium2_sk = Dilithium2SecretKey(SecretBox::new(Box::new(arr)));
    let dilithium2_signature = Dilithium2::sign(signing_input.as_bytes(), &dilithium2_sk)
        .map_err(|_| AppError::InvalidSecretKey)?;
    let dilithium2_signature_base64 = encode_base64_url(&dilithium2_signature.0);

    let sigs_json = json!({
        "es256": es256_signature_base64,
        "dilithium2": dilithium2_signature_base64,
    });

    let sigs_b64 =
        encode_base64_url(&serde_json::to_vec(&sigs_json).map_err(|_| AppError::InvalidBase64)?);

    let jwt = format!("{}.{}.{}", header_base64, payload_base64, sigs_b64);
    Ok(Json(HybridSignResponse { jwt }))
}
