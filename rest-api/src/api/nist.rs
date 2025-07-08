use axum::{Router, routing::get};
use crate::handlers::nist_compliance;

pub fn routes() -> Router {
    Router::new()
        .route("/nist/compliance", get(nist_compliance::nist_compliance_info))
        .route("/nist/deprecation", get(nist_compliance::deprecation_warnings))
}