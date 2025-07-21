use crate::handlers::hybrid_handler;
use axum::{routing::post, Router};

pub fn routes() -> Router {
    Router::new().route("/hybrid/sign", post(hybrid_handler::sign_hybrid_jwt))
}
