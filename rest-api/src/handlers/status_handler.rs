use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{Html, Response},
};
use std::path::PathBuf;
use tokio::fs;

pub async fn serve_status_page() -> Result<Html<String>, (StatusCode, &'static str)> {
    match fs::read_to_string("static/index.html").await {
        Ok(content) => Ok(Html(content)),
        Err(_) => Err((StatusCode::NOT_FOUND, "Status page not found")),
    }
}

pub async fn serve_static_index() -> Result<Html<String>, StatusCode> {
    match fs::read_to_string("static/index.html").await {
        Ok(content) => Ok(Html(content)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn serve_static_file(
    Path(path): Path<String>,
) -> Result<Response, (StatusCode, &'static str)> {
    // Security: Prevent path traversal attacks
    if path.contains("..") || path.contains("/./") || path.starts_with('/') {
        return Err((StatusCode::BAD_REQUEST, "Invalid path"));
    }

    let file_path = PathBuf::from("static").join(&path);
    
    // Ensure we're only serving files from the static directory
    if !file_path.starts_with("static/") {
        return Err((StatusCode::BAD_REQUEST, "Invalid path"));
    }

    let content = match fs::read(&file_path).await {
        Ok(content) => content,
        Err(_) => return Err((StatusCode::NOT_FOUND, "File not found")),
    };

    let content_type = get_content_type(&path);
    
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "public, max-age=3600") // Cache for 1 hour
        .body(content.into())
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build response"))?;

    Ok(response)
}

fn get_content_type(path: &str) -> &'static str {
    let extension = path.split('.').last().unwrap_or("");
    
    match extension {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "eot" => "application/vnd.ms-fontobject",
        _ => "application/octet-stream",
    }
}