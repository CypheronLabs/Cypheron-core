use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct HybridSignRequest {
    pub message: String,
    pub es256: String,
    pub dilithium2_sk: String,
}

#[derive(Serialize)]
pub struct HybridSignResponse {
    pub jwt: String,
}
