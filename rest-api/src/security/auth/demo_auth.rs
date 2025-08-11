use serde::{Deserialize, Serialize};

use super::jwt_validation::DemoTokenClaims;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoUser {
    pub sub: String,
    pub tier: String,
    pub permissions: Vec<String>,
    pub expires_at: u64,
}

impl From<DemoTokenClaims> for DemoUser {
    fn from(claims: DemoTokenClaims) -> Self {
        Self {
            sub: claims.sub,
            tier: claims.tier,
            permissions: create_demo_permissions(),
            expires_at: claims.exp,
        }
    }
}

pub fn create_demo_permissions() -> Vec<String> {
    vec![
        "kem:encapsulate".to_string(),
        "sig:verify".to_string(),
        "hybrid:sign".to_string(),
        "nist:read".to_string(),
        "monitoring:read".to_string(),
    ]
}

pub fn check_demo_permission(demo_user: &DemoUser, resource: &str) -> bool {
    for permission in &demo_user.permissions {
        if permission == "*" {
            return true;
        }
        
        if permission == resource {
            return true;
        }
        
        if permission.ends_with(":*") {
            let prefix = &permission[..permission.len() - 1];
            if resource.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

#[derive(Debug, Clone)]
pub struct DemoContext {
    pub user: DemoUser,
    pub request_id: String,
}

impl DemoContext {
    pub fn new(user: DemoUser, request_id: String) -> Self {
        Self { user, request_id }
    }

    pub fn has_permission(&self, resource: &str) -> bool {
        check_demo_permission(&self.user, resource)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_demo_user() -> DemoUser {
        DemoUser {
            sub: "demo_user".to_string(),
            tier: "demo".to_string(),
            permissions: create_demo_permissions(),
            expires_at: 1234567890,
        }
    }

    #[test]
    fn test_demo_permissions_creation() {
        let permissions = create_demo_permissions();
        assert!(permissions.contains(&"kem:encapsulate".to_string()));
        assert!(permissions.contains(&"sig:verify".to_string()));
        assert!(permissions.contains(&"hybrid:sign".to_string()));
        assert!(permissions.contains(&"nist:read".to_string()));
        assert!(permissions.contains(&"monitoring:read".to_string()));
    }

    #[test]
    fn test_check_demo_permission_exact_match() {
        let demo_user = create_test_demo_user();
        assert!(check_demo_permission(&demo_user, "kem:encapsulate"));
        assert!(check_demo_permission(&demo_user, "sig:verify"));
    }

    #[test]
    fn test_check_demo_permission_wildcard() {
        let mut demo_user = create_test_demo_user();
        demo_user.permissions = vec!["kem:*".to_string()];
        
        assert!(check_demo_permission(&demo_user, "kem:encapsulate"));
        assert!(check_demo_permission(&demo_user, "kem:decapsulate"));
        assert!(!check_demo_permission(&demo_user, "sig:verify"));
    }

    #[test]
    fn test_check_demo_permission_wildcard_all() {
        let mut demo_user = create_test_demo_user();
        demo_user.permissions = vec!["*".to_string()];
        
        assert!(check_demo_permission(&demo_user, "kem:encapsulate"));
        assert!(check_demo_permission(&demo_user, "sig:verify"));
        assert!(check_demo_permission(&demo_user, "admin:manage"));
    }

    #[test]
    fn test_check_demo_permission_no_access() {
        let demo_user = create_test_demo_user();
        assert!(!check_demo_permission(&demo_user, "admin:manage"));
        assert!(!check_demo_permission(&demo_user, "kem:keygen"));
    }

    #[test]
    fn test_demo_context_has_permission() {
        let demo_user = create_test_demo_user();
        let context = DemoContext::new(demo_user, "req_123".to_string());
        
        assert!(context.has_permission("kem:encapsulate"));
        assert!(!context.has_permission("admin:manage"));
    }

    #[test]
    fn test_demo_user_from_claims() {
        use super::super::jwt_validation::DemoTokenClaims;
        
        let claims = DemoTokenClaims {
            sub: "test_user".to_string(),
            tier: "demo".to_string(),
            exp: 1234567890,
            iat: 1234567800,
        };
        
        let demo_user = DemoUser::from(claims);
        assert_eq!(demo_user.sub, "test_user");
        assert_eq!(demo_user.tier, "demo");
        assert_eq!(demo_user.expires_at, 1234567890);
        assert!(!demo_user.permissions.is_empty());
    }
}