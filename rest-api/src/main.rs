use axum::serve;
use tokio::net::TcpListener;
use tracing_subscriber;

mod api;
mod handlers;
mod models;
mod services;
mod error;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = api::kem::routes();

    let listener = TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind port");

    tracing::info!("Listening on http://127.0.0.1:3000");

    serve(listener, app)
        .await
        .expect("Server error");
}