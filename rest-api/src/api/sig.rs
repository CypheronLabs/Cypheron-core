use axum::{Router, routing::post};
use crate::handlers::sig_handler;
use crate::security::AuditLogger;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AuditLogger>> {
    Router::new()
        .route("/sig/{variant}/keygen", post(sig_handler::keygen))
        .route("/sig/{variant}/sign", post(sig_handler::sign))
        .route("/sig/{variant}/verify", post(sig_handler::verify))
}