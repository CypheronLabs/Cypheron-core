# Cypheron Security Architecture

## Overview

The Cypheron REST API implements a multi-layered security architecture designed for post-quantum cryptographic operations. The security system is built with defense-in-depth principles, incorporating authentication, authorization, audit logging, rate limiting, compliance monitoring, and request timeout management.

## Security Components

### 1. Authentication System (`auth.rs`)

#### Post-Quantum Encryption (`PostQuantumEncryption`)

- **Encryption Algorithm**: AES-256-GCM with 12-byte nonces
- **Key Derivation**: PBKDF2 with 10,000 iterations using SHA-256
- **Salt Generation**: 16-byte cryptographically secure random salts
- **Purpose**: Encrypts sensitive data including API keys before storage

```rust
impl PostQuantumEncryption {
    pub fn encrypt_data(&self, data: &str, password: &str) -> Result<EncryptedData, SecurityError>
    pub fn decrypt_data(&self, encrypted_data: &EncryptedData, password: &str) -> Result<String, SecurityError>
}
```

#### API Key Management (`ApiKeyStore`)

- **Storage Backend**: Google Cloud Firestore integration
- **Key Structure**:
  - Unique UUID identifier
  - SHA-256 hashed key for verification
  - Configurable permissions and rate limits
  - Expiration dates and usage tracking
- **Security Features**:
  - Constant-time key verification to prevent timing attacks
  - Encrypted storage using PostQuantumEncryption
  - Usage count and last-used tracking

#### Authentication Flow

1. **API Key Extraction**: Bearer token from Authorization header
2. **Key Validation**: SHA-256 hash comparison with stored keys
3. **Permission Check**: Validates required permissions for endpoint
4. **Rate Limit Check**: Enforces per-key rate limits
5. **Audit Logging**: Records all authentication attempts

### 2. Middleware Layer (`middleware.rs`)

#### Security Middleware Stack

- **Authentication Middleware**: Validates API keys for protected routes
- **Rate Limiting**: Per-IP and per-API-key rate limiting
- **Request Timeout**: Smart timeout based on endpoint complexity
- **Audit Logging**: Comprehensive request/response logging
- **CORS Handling**: Configurable cross-origin resource sharing

#### Request Processing Pipeline

```
Incoming Request → CORS → Rate Limit → Timeout → Authentication → Route Handler
```

### 3. Rate Limiting System (`rate_limit.rs`)

#### Features

- **Sliding Window**: 60-second rate limit windows
- **IP-based Limiting**: Fallback to IP address when API key unavailable
- **Secure Fallback**: Header-based fingerprinting for privacy
- **Configurable Limits**: Per-endpoint rate limits (default: 60 requests/minute)
- **Block Duration**: 60-second penalty for rate limit violations

#### Rate Limit Algorithm

```rust
pub struct RateLimitEntry {
    pub count: u32,
    pub window_start: Instant,
    pub blocked_until: Option<Instant>,
}
```

### 4. Audit Logging (`audit.rs`)

#### Event Types

- **API Operations**: Key creation, usage, expiration
- **Security Events**: Authentication failures, authorization denials
- **System Events**: Rate limit violations, suspicious activity
- **Crypto Operations**: Cryptographic operations and verifications

#### Audit Event Structure

```rust
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub api_key_id: Option<Uuid>,
    pub ip_address: String,
    pub response_status: u16,
    pub response_time_ms: u64,
    // Additional contextual data
}
```

#### Features

- **Structured Logging**: JSON-formatted audit trails
- **Event Filtering**: Query by type, API key, or time range
- **Security Alerts**: Automatic warnings for high-risk events
- **Data Retention**: Configurable retention periods

### 5. Compliance Framework (`compliance.rs`)

#### SOC 2 Implementation

The compliance system addresses all five Trust Services Criteria:

##### Security (CC6.0)

- Authentication and authorization controls
- Access monitoring and violation detection
- Security incident logging

##### Availability (CC7.0)

- System access monitoring
- Performance and capacity alerts
- Error tracking and reporting

##### Processing Integrity (CC8.0)

- Change management logging
- Configuration update tracking
- Code deployment auditing

##### Confidentiality (CC9.0)

- Data encryption tracking
- Access control enforcement
- Sensitive data handling

##### Privacy (P1.0)

- Personal data access logging
- Consent management
- Data minimization and pseudonymization

#### Compliance Features

```rust
pub struct ComplianceManager {
    // Event tracking with risk assessment
    pub async fn log_event(&self, event_type: ComplianceEventType, risk_level: RiskLevel)
    
    // Data processing records for GDPR compliance
    pub async fn record_data_processing(&self, operation: String, data_type: String)
    
    // Access validation with permission checks
    pub async fn validate_access(&self, user_id: &str, required_permission: &str) -> bool
    
    // Automated compliance reporting
    pub async fn generate_compliance_report(&self) -> ComplianceReport
}
```

#### Privacy Controls

- **Pseudonymization**: User ID hashing for privacy protection
- **Data Sanitization**: Automatic PII removal from logs
- **Retention Policies**: Automated old data cleanup
- **Data Minimization**: Only necessary data in compliance logs

### 6. Timeout Management (`timeout.rs`)

#### Smart Timeout Strategy

Different endpoints have optimized timeout values based on operation complexity:

- **Cryptographic Operations**: 45 seconds (KEM/signature operations)
- **Health Checks**: 5 seconds (quick status responses)
- **Admin Operations**: 30 seconds (management tasks)
- **Monitoring/NIST**: 15 seconds (compliance checks)
- **Default**: 15 seconds (other endpoints)

#### Connection Management

- **Concurrency Limits**: Configurable maximum concurrent connections
- **Request Size Limits**: 1MB maximum request body size
- **Global Timeouts**: Fallback timeout for all requests

### 7. API Key Management (`api_key.rs`)

#### Key Generation

- **Format**: `pq-{32-character-alphanumeric}`
- **Entropy**: Cryptographically secure random generation
- **Uniqueness**: UUID-based identification

#### Permission System

Granular permissions for different operations:

```rust
let valid_permissions = [
    "kem:*", "kem:keygen", "kem:encapsulate", "kem:decapsulate",
    "sig:*", "sig:keygen", "sig:sign", "sig:verify",
    "hybrid:*", "hybrid:sign",
    "*"  // Full access
];
```

#### Administrative Endpoints

- `POST /admin/api-keys`: Create new API keys
- `GET /admin/api-keys`: List existing keys
- `GET /admin/api-keys/{id}`: Get specific key information

## Security Best Practices

### 1. Defense in Depth

- Multiple security layers prevent single points of failure
- Each component validates and enforces security independently
- Audit logging provides comprehensive visibility

### 2. Cryptographic Security

- Post-quantum safe encryption algorithms
- Proper key derivation and salt generation
- Constant-time operations to prevent timing attacks

### 3. Access Control

- Principle of least privilege in permission system
- Time-based key expiration
- Usage tracking and monitoring

### 4. Monitoring and Alerting

- Real-time security event detection
- Automated compliance monitoring
- Structured audit trails for investigation

### 5. Privacy Protection

- Data minimization in logs
- Pseudonymization of sensitive identifiers
- Configurable data retention policies

## Configuration

### Environment Variables

```bash
# Firestore Configuration
GOOGLE_CLOUD_PROJECT_ID=your-project-id
FIRESTORE_COLLECTION=api_keys
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Security Configuration
RATE_LIMIT_REQUESTS_PER_MINUTE=60
API_KEY_EXPIRATION_DAYS=90
AUDIT_LOG_RETENTION_DAYS=365

# Encryption
MASTER_PASSWORD=your-secure-master-password
```

### Security Hardening

1. **Network Security**: Use HTTPS/TLS 1.3 for all communications
2. **Key Rotation**: Regular API key rotation policies
3. **Monitoring**: Deploy security event monitoring
4. **Backup**: Secure backup of Firestore data
5. **Access**: Restrict admin endpoint access

## Integration Points

The security system integrates with:

- **Firestore**: Persistent API key storage
- **Axum Framework**: Middleware and routing
- **Ring Cryptography**: Encryption operations
- **Tracing**: Structured logging
- **Google Cloud SDK**: Firestore client

## Identified Security Flaws and Recommendations

### Critical Security Issues

#### 1. **Master Password Fallback Vulnerability** (`auth.rs`)

```rust
let master_password = std::env::var("MASTER_PASSWORD")
    .unwrap_or_else(|_| "default_insecure_password".to_string());
```

**Issue**: Falls back to hardcoded default password if environment variable is missing.
**Risk**: Critical - Complete compromise of all encrypted API keys.
**Fix**: Remove fallback and fail fast if master password is not set.

#### 2. **Rate Limiting Bypass** (`rate_limit.rs`)

**Issue**: Rate limiting can be bypassed by clients behind load balancers or proxies.
**Risk**: High - Denial of service and resource exhaustion attacks.
**Fix**: Implement API key-based rate limiting as primary method with IP as fallback.

#### 3. **Incomplete API Key Validation** (`auth.rs`)

**Issue**: Authentication only checks hash but doesn't validate expiration, active status, or usage limits.
**Risk**: High - Expired or disabled keys can still access the system.
**Fix**: Add comprehensive validation in `verify_api_key_constant_time`.

#### 4. **Error Information Leakage** (`api_key.rs`)

```rust
message: format!("Failed to store API key: {}", e.message)
```

**Issue**: Internal error details exposed to clients.
**Risk**: Medium - Information disclosure about system architecture.
**Fix**: Sanitize error messages and log detailed errors internally only.

### Implementation Gaps

#### 5. **Incomplete Firestore Operations** (`auth.rs`)

**Issue**: Several CRUD operations return `Ok(())` without implementation:

- `update_api_key`
- `delete_api_key`
- `list_api_keys`
**Risk**: Medium - Incomplete functionality affects system management.
**Fix**: Implement complete Firestore CRUD operations.

#### 6. **Memory Security Vulnerability**

**Issue**: API keys remain in memory as strings, vulnerable to memory dumps.
**Risk**: Medium - Sensitive data exposure through memory analysis.
**Fix**: Use secure string types and clear sensitive data after use.

#### 7. **Insufficient Audit Logging** (`middleware.rs`)

**Issue**: Missing security-relevant event logging:

- Failed authentication attempts with context
- Permission denials
- Rate limit violations
**Risk**: Medium - Reduced security visibility and incident response capability.
**Fix**: Implement comprehensive security event logging.

### Design Flaws

#### 8. **Single Point of Failure**

**Issue**: Master password is single point of failure for all encrypted data.
**Risk**: High - Complete system compromise if master password is leaked.
**Fix**: Implement key rotation mechanism and consider HSM integration.

#### 9. **No Key Rotation Mechanism**

**Issue**: No built-in support for:

- Master password rotation
- API key rotation policies
- Encrypted data migration
**Risk**: Medium - Inability to respond to key compromise scenarios.
**Fix**: Design and implement key rotation workflows.

#### 10. **Compliance Control Gaps** (`compliance.rs`)

```rust
vulnerability_scanning_enabled: false,
backup_procedures_active: false,
```

**Issue**: Critical security controls disabled by default.
**Risk**: High - SOC 2 compliance violations and security gaps.
**Fix**: Enable all required security controls and implement missing features.

### Immediate Action Items

#### Priority 1 (Critical - Fix Immediately)

1. Remove master password fallback mechanism
2. Implement complete API key validation
3. Enable all compliance security controls
4. Complete Firestore CRUD operations

#### Priority 2 (High - Fix Within Sprint)

1. Implement API key-based rate limiting
2. Add comprehensive audit logging
3. Sanitize all error messages
4. Add memory security measures

#### Priority 3 (Medium - Plan for Next Release)

1. Design key rotation mechanism
2. Implement advanced monitoring
3. Add behavioral anomaly detection
4. Enhance backup and recovery procedures

### Security Testing Requirements

1. **Penetration Testing**: External security assessment
2. **Code Review**: Security-focused code audit
3. **Compliance Audit**: SOC 2 readiness assessment
4. **Load Testing**: Rate limiting and DoS resistance
5. **Recovery Testing**: Backup and disaster recovery validation

## Future Enhancements

1. **Hardware Security Modules (HSM)**: Key storage in dedicated hardware
2. **OAuth 2.0**: Additional authentication methods
3. **JWT Tokens**: Session-based authentication
4. **Multi-factor Authentication**: Enhanced security for admin operations
5. **Anomaly Detection**: ML-based suspicious activity detection
