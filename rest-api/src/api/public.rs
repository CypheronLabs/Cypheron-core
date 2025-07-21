use axum::{response::Json, routing::get, Router};

pub async fn get_api_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "operational",
        "version": "0.2.0",
        "features": [
            "ML-KEM Key Encapsulation",
            "ML-DSA Digital Signatures",
            "Hybrid Cryptography",
            "NIST Compliance"
        ],
        "compliance": {
            "fips_203": true,
            "fips_204": true,
            "fips_205": true
        },
        "encryption": "Post-Quantum (ML-KEM-768 + ChaCha20-Poly1305)"
    }))
}

pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/public/status", get(get_api_status))
}
