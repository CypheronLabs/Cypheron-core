use crate::handlers::sig_handler;
use crate::security::AuditLogger;
use axum::extract::FromRef;
use axum::{routing::post, Router};
use std::sync::Arc;

pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    Arc<AuditLogger>: FromRef<S>,
{
    Router::new()
        .route("/sig/{variant}/keygen", post(sig_handler::keygen))
        .route("/sig/{variant}/sign", post(sig_handler::sign))
        .route("/sig/{variant}/verify", post(sig_handler::verify))
}
