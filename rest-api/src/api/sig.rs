use axum::{Router, routing::post};
use crate::handlers::sig_handler;
pub fn routes() -> Router {
    Router::new()
        .route("/sig/{variant}/keygen", post(sig_handler::keygen))
        .route("/sig/{variant}/sign", post(sig_handler::sign))
        .route("/sig/{variant}/verify", post(sig_handler::verify))
}