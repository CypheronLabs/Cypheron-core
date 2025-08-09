use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
    pub message: String,
    pub code: u16,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} (code: {})", self.error, self.message, self.code)
    }
}

impl std::error::Error for AuthError {}