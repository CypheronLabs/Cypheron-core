use crate::handlers::nist_compliance;
use axum::{routing::get, Router};

pub fn routes() -> Router {
    Router::new()
        .route("/nist/compliance", get(nist_compliance::nist_compliance_info))
        .route("/nist/deprecation", get(nist_compliance::deprecation_warnings))
}
