use axum::{Router, routing::post};
use crate::handlers::hybrid_handler;

pub fn routes() -> Router {
    Router::new()
        .route("/hybrid/sign", post(hybrid_handler::sign_hybrid_jwt))
}