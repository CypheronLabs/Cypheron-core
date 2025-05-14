use serde::{Serialize, Deserialize};

#[derive(Deserialize)]
pub struct EncapsulateRequest {
    pub pk: String,
}
#[derive(Deserialize)]
pub  struct DecapsulateRequest {
    pub ct: String,
    pub sk: String,
}
#[derive(Serialize)]
pub struct KeypairResponse {
    pub pk: String,
    pub sk: String,
}
#[derive(Serialize)]
pub struct EncapsulateResponse {
    pub ct: String,
    pub ss: String,
}
#[derive(Serialize)]
pub struct DecapsulateResponse {
    pub ss: String,
}