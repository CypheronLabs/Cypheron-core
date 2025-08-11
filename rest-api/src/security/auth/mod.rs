pub mod demo_auth;
pub mod encryption;
pub mod errors;
pub mod hybrid_encryption;
pub mod jwt_middleware;
pub mod jwt_validation;
pub mod middleware;
pub mod models;
pub mod permissions;
pub mod repository;
pub mod store;
pub mod utils;
pub mod validation;

#[cfg(test)]
pub mod tests;

pub use demo_auth::{DemoContext, DemoUser, check_demo_permission, create_demo_permissions};
pub use encryption::PostQuantumEncryption;
pub use errors::AuthError;
pub use hybrid_encryption::{HybridEncryption, VersionedEncryptedData, EncryptionVersion};
pub use jwt_middleware::jwt_auth_middleware;
pub use jwt_validation::{JwtValidator, DemoTokenClaims, JwtError};
pub use middleware::{admin_auth_middleware, auth_middleware, compliance_middleware};
pub use models::ApiKey;
pub use permissions::{check_permission, extract_resource_from_path};
pub use repository::FirestoreApiKeyRepository;
pub use store::ApiKeyStore;
pub use utils::extract_api_key;
pub use validation::KeyValidator;