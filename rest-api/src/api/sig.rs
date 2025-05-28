use axum::{Router, routing::post};
use crate::handlers::sig_handler;
pub fn routes() -> Router {
    Router::new()
        .route("/:variant/keygen", post(sig_handler::keygen))
        .route("/:variant/sign", post(sig_handler::sign))
        .route("/:variant/verify", post(sig_handler::verify))
}