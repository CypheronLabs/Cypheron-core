use axum::{Router, routing::{post, get}};
use crate::handlers::kem_handler;
use crate::security::AuditLogger;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AuditLogger>> {
    Router::new()
        .route("/kem/{variant}/keygen", post(kem_handler::keygen))
        .route("/kem/{variant}/encapsulate", post(kem_handler::encapsulate))
        .route("/kem/{variant}/decapsulate", post(kem_handler::decapsulate))
        .route("/kem/{variant}/info", get(kem_handler::variant_info)) // New info endpoint
}