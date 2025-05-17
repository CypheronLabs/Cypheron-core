use axum::{Router, routing::post};
// Update this import to match your actual handlers module structure.
// For example, if the functions are in `handlers/sig.rs` and declared as `pub`, use:
use crate::handlers::sig_handler;

// Or, if you want to create `sig_handler.rs`, create the file and define the required functions there.

pub fn routes() -> Router {
    Router::new()
        .route("/:variant/keygen", post(sig_handler::keygen))
        .route("/:variant/sign", post(sig_handler::sign))
        .route("/:variant/verify", post(sig_handler::verify))
}