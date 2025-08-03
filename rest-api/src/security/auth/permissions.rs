use subtle::ConstantTimeEq;

use super::models::ApiKey;

pub fn extract_resource_from_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return "root".to_string();
    }

    match segments[0] {
        "kem" => format!("kem:{}", segments.get(2).unwrap_or(&"*")),
        "sig" => format!("sig:{}", segments.get(2).unwrap_or(&"*")),
        "hybrid" => "hybrid:sign".to_string(),
        "monitoring" => "monitoring:read".to_string(),
        "admin" => "admin:manage".to_string(),
        "nist" => "nist:read".to_string(),
        _ => "unknown".to_string(),
    }
}

pub fn check_permission(api_key: &ApiKey, resource: &str) -> bool {
    let mut has_permission = false;

    for permission in &api_key.permissions {
        let exact_match = permission.as_bytes().ct_eq(b"*").into()
            || permission.as_bytes().ct_eq(resource.as_bytes()).into();

        let wildcard_match = if permission.ends_with(":*") {
            let prefix = &permission[..permission.len() - 1];
            resource.starts_with(prefix)
        } else {
            false
        };

        has_permission |= exact_match || wildcard_match;
    }

    has_permission
}