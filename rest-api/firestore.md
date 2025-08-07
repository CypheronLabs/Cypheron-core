# Cypheron Firestore Integration

## Overview

The Cypheron REST API uses Google Cloud Firestore as the primary database for storing API keys and related metadata. The integration implements post-quantum encryption for data-at-rest protection and follows Google Cloud best practices for security and performance.

## Architecture

### Database Design

#### Collection Structure

```
api_keys/
├── {api_key_id}/
│   ├── id: UUID
│   ├── name: String
│   ├── key_hash: String (SHA-256)
│   ├── encrypted_key: EncryptedData
│   ├── permissions: Array<String>
│   ├── rate_limit: Number
│   ├── created_at: Timestamp
│   ├── expires_at: Timestamp (optional)
│   ├── is_active: Boolean
│   ├── last_used: Timestamp (optional)
│   └── usage_count: Number
```

### Integration Components

#### 1. Firestore Client (`FirestoreApiKeyStore`)

The `FirestoreApiKeyStore` struct implements the `ApiKeyStore` trait and provides the primary interface for Firestore operations:

```rust
pub struct FirestoreApiKeyStore {
    client: FirestoreClient,
    project_id: String,
    collection_name: String,
    encryption: PostQuantumEncryption,
}
```

#### Configuration

- **Project ID**: From `GOOGLE_CLOUD_PROJECT_ID` environment variable
- **Collection Name**: From `FIRESTORE_COLLECTION` environment variable (default: "api_keys")
- **Authentication**: Service account credentials via `GOOGLE_APPLICATION_CREDENTIALS`

#### 2. Data Encryption Layer

All sensitive data is encrypted before storage using the `PostQuantumEncryption` component:

##### Encryption Specifications

- **Algorithm**: AES-256-GCM
- **Key Derivation**: PBKDF2 with 10,000 iterations
- **Salt**: 16-byte random salt per encryption
- **Nonce**: 12-byte random nonce per encryption

##### Encrypted Data Structure

```rust
pub struct EncryptedData {
    pub encrypted_content: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}
```

## Core Operations

### 1. Store API Key

```rust
pub async fn store_api_key(&self, api_key: &ApiKey, raw_key: &str) -> Result<(), FirestoreError>
```

**Process Flow:**

1. Encrypts the raw API key using PostQuantumEncryption
2. Converts API key metadata to Firestore `Value` format
3. Creates document in Firestore collection
4. Handles encryption and storage errors

**Firestore Document Creation:**

```rust
let create_request = CreateDocumentRequest {
    parent: format!("projects/{}/databases/(default)/documents/{}", 
                   self.project_id, self.collection_name),
    collection_id: self.collection_name.clone(),
    document_id: api_key.id.to_string(),
    document: Some(document),
    mask: None,
};
```

### 2. Retrieve API Key

```rust
pub async fn get_api_key_by_hash(&self, key_hash: &str) -> Result<Option<(ApiKey, String)>, FirestoreError>
```

**Process Flow:**

1. Queries Firestore for document with matching key hash
2. Retrieves and decrypts the stored raw key
3. Reconstructs the `ApiKey` struct from Firestore data
4. Returns both the API key metadata and decrypted raw key

**Query Implementation:**

```rust
let get_request = GetDocumentRequest {
    name: document_path,
    mask: None,
    consistency_selector: None,
};
```

### 3. Update API Key

```rust
pub async fn update_api_key(&self, api_key: &ApiKey) -> Result<(), FirestoreError>
```

**Process Flow:**

1. Converts updated API key data to Firestore format
2. Updates specific fields while preserving encrypted key data
3. Handles concurrent modification scenarios

### 4. Delete API Key

```rust
pub async fn delete_api_key(&self, api_key_id: &Uuid) -> Result<(), FirestoreError>
```

**Process Flow:**

1. Locates document by API key ID
2. Securely deletes from Firestore
3. Ensures complete removal of sensitive data

## Data Conversion Layer

### Rust to Firestore (`to_firestore_value`)

Converts Rust data types to Firestore `Value` format:

```rust
fn to_firestore_value(api_key: &ApiKey, encrypted_key: &EncryptedData) -> Value {
    let mut fields = std::collections::HashMap::new();
    
    // String fields
    fields.insert("id".to_string(), Value {
        value_type: Some(google::firestore::v1::value::ValueType::StringValue(
            api_key.id.to_string()
        )),
    });
    
    // Array fields (permissions)
    fields.insert("permissions".to_string(), Value {
        value_type: Some(google::firestore::v1::value::ValueType::ArrayValue(
            ArrayValue {
                values: api_key.permissions.iter().map(|p| Value {
                    value_type: Some(google::firestore::v1::value::ValueType::StringValue(
                        p.clone()
                    )),
                }).collect(),
            }
        )),
    });
    
    // Encrypted data storage
    fields.insert("encrypted_key_content".to_string(), /* base64 encoded bytes */);
    fields.insert("encrypted_key_salt".to_string(), /* base64 encoded bytes */);
    fields.insert("encrypted_key_nonce".to_string(), /* base64 encoded bytes */);
}
```

### Firestore to Rust (`from_firestore_document`)

Converts Firestore documents back to Rust structs:

```rust
fn from_firestore_document(document: &Document) -> Result<(ApiKey, EncryptedData), FirestoreError> {
    let fields = &document.fields;
    
    // Extract and validate required fields
    let id = extract_string_field(fields, "id")?;
    let name = extract_string_field(fields, "name")?;
    let permissions = extract_array_field(fields, "permissions")?;
    
    // Reconstruct encrypted data
    let encrypted_data = EncryptedData {
        encrypted_content: base64::decode(extract_string_field(fields, "encrypted_key_content")?)?,
        salt: base64::decode(extract_string_field(fields, "encrypted_key_salt")?)?,
        nonce: base64::decode(extract_string_field(fields, "encrypted_key_nonce")?)?,
    };
    
    Ok((api_key, encrypted_data))
}
```

## Error Handling

### FirestoreError Types

```rust
pub enum FirestoreError {
    ConnectionError(String),
    SerializationError(String), 
    EncryptionError(String),
    DocumentNotFound,
    PermissionDenied,
    InvalidData(String),
    ClientError(String),
}
```

### Error Recovery Strategies

1. **Connection Failures**: Automatic retry with exponential backoff
2. **Serialization Errors**: Data validation and graceful degradation
3. **Encryption Errors**: Secure error logging without exposing keys
4. **Document Not Found**: Proper null handling in API responses
5. **Permission Denied**: Authentication re-validation

## Security Considerations

### 1. Encryption at Rest

- All API keys encrypted before Firestore storage
- Master password from secure environment variable
- Unique salt and nonce for each encryption operation

### 2. Network Security

- All Firestore communications over TLS 1.3
- Google Cloud IAM for service authentication
- Private service account keys for API access

### 3. Access Control

- Service account with minimal required permissions
- Firestore security rules for additional protection
- Audit logging for all database operations

### 4. Data Privacy

- No plaintext API keys stored in Firestore
- Encrypted data cannot be decrypted without master password
- Zero-knowledge architecture for key storage

## Performance Optimization

### 1. Query Optimization

- Efficient indexing on frequently queried fields
- Batch operations for multiple key operations
- Connection pooling for concurrent requests

### 2. Caching Strategy

- In-memory caching of frequently accessed keys
- TTL-based cache invalidation
- Cache warming for critical API keys

### 3. Connection Management

- Persistent Firestore client connections
- Connection pooling configuration
- Graceful connection handling and recovery

## Monitoring and Observability

### 1. Metrics Collection

- Operation latency tracking
- Error rate monitoring
- Connection health metrics
- Query performance analysis

### 2. Logging Strategy

- Structured logging for all Firestore operations
- Error logging with context preservation
- Debug logging for development environments
- Security event logging for audit trails

### 3. Alerting

- High error rate alerts
- Connection failure notifications
- Performance degradation warnings
- Unusual access pattern detection

## Configuration

### Environment Variables

```bash
# Required Configuration
GOOGLE_CLOUD_PROJECT_ID=your-gcp-project-id
FIRESTORE_COLLECTION=api_keys
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Optional Configuration
FIRESTORE_TIMEOUT_SECONDS=30
FIRESTORE_RETRY_ATTEMPTS=3
FIRESTORE_CONNECTION_POOL_SIZE=10

# Encryption Configuration
MASTER_PASSWORD=your-secure-master-password
ENCRYPTION_KEY_DERIVATION_ITERATIONS=10000
```

### Service Account Permissions

Required IAM roles for the service account:

```json
{
  "roles": [
    "roles/datastore.user",
    "roles/firestore.viewer",
    "roles/firestore.editor"
  ],
  "resources": [
    "projects/your-project-id/databases/(default)/documents/api_keys/*"
  ]
}
```

### Firestore Security Rules

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /api_keys/{document} {
      allow read, write: if request.auth != null 
        && request.auth.token.aud == 'your-project-id';
    }
  }
}
```

## Backup and Disaster Recovery

### 1. Automated Backups

- Daily Firestore exports to Cloud Storage
- Point-in-time recovery capabilities
- Cross-region backup replication

### 2. Data Recovery Procedures

- Documented recovery processes
- Test recovery procedures regularly
- Encryption key backup strategies

### 3. Business Continuity

- Multi-region Firestore deployment
- Failover procedures for service disruptions
- Data consistency validation post-recovery

## Development and Testing

### 1. Local Development

- Firestore emulator for local testing
- Test data seeding and cleanup
- Mock implementations for unit tests

### 2. Integration Testing

- End-to-end API key lifecycle tests
- Encryption/decryption validation
- Error condition testing

### 3. Load Testing

- Concurrent operation testing
- Performance benchmarking
- Stress testing for peak loads

## Migration and Maintenance

### 1. Schema Evolution

- Backward-compatible field additions
- Data migration procedures
- Version management strategies

### 2. Maintenance Windows

- Planned maintenance procedures
- Zero-downtime deployment strategies
- Database optimization schedules

### 3. Capacity Planning

- Storage growth monitoring
- Query performance tracking
- Resource utilization analysis

## Identified Flaws and Areas for Improvement

### Critical Issues

#### 1. **Master Password Security Risk**

**Issue**: Single master password protects all encrypted API keys in Firestore.
**Risk**: Complete data compromise if master password is leaked or guessed.
**Impact**: All stored API keys become accessible to attackers.
**Recommendation**:

- Implement key rotation mechanism
- Consider Hardware Security Module (HSM) integration
- Add multi-layer encryption with different keys

#### 2. **Incomplete CRUD Operations**

**Issue**: Several Firestore operations are not fully implemented:

```rust
// These return Ok(()) without actual implementation
pub async fn update_api_key(&self, api_key: &ApiKey) -> Result<(), FirestoreError>
pub async fn delete_api_key(&self, api_key_id: &Uuid) -> Result<(), FirestoreError>
```

**Risk**: System management and maintenance capabilities are limited.
**Impact**: Cannot properly manage API key lifecycle.
**Recommendation**: Complete implementation of all CRUD operations.

#### 3. **Query Inefficiency**

**Issue**: Current implementation queries by hash, requiring full collection scan.
**Risk**: Performance degradation as API key count grows.
**Impact**: Slower authentication and increased Firestore costs.
**Recommendation**:

- Create composite indexes on frequently queried fields
- Implement efficient query patterns
- Add caching layer for frequently accessed keys

### Security Concerns

#### 4. **Error Information Disclosure**

**Issue**: Firestore errors may expose internal system details.
**Risk**: Information leakage about database structure and implementation.
**Impact**: Potential attack vector discovery.
**Recommendation**: Sanitize all error messages before returning to clients.

#### 5. **No Concurrent Modification Handling**

**Issue**: Updates don't handle concurrent modifications or version conflicts.
**Risk**: Data corruption or lost updates in high-concurrency scenarios.
**Impact**: Inconsistent API key state.
**Recommendation**: Implement optimistic locking with document versioning.

#### 6. **Insufficient Access Validation**

**Issue**: Firestore security rules are basic and don't validate field-level permissions.
**Risk**: Potential unauthorized data access or modification.
**Impact**: Privilege escalation or data tampering.
**Recommendation**: Implement comprehensive security rules with field-level validation.

### Performance and Scalability Issues

#### 7. **No Connection Pooling**

**Issue**: Each operation creates new Firestore client connections.
**Risk**: Resource exhaustion and increased latency.
**Impact**: Poor performance under load.
**Recommendation**: Implement connection pooling and reuse.

#### 8. **Missing Batch Operations**

**Issue**: No support for bulk operations on multiple API keys.
**Risk**: Inefficient processing of large datasets.
**Impact**: High latency and increased costs for bulk operations.
**Recommendation**: Implement batch read/write operations.

#### 9. **No Caching Strategy**

**Issue**: Every API key lookup hits Firestore directly.
**Risk**: Unnecessary database load and latency.
**Impact**: Poor performance and high costs.
**Recommendation**: Implement intelligent caching with TTL and invalidation.

### Data Integrity and Backup Concerns

#### 10. **No Data Validation**

**Issue**: Stored data isn't validated for completeness or correctness.
**Risk**: Corrupted or incomplete data in Firestore.
**Impact**: System failures and data loss.
**Recommendation**: Add comprehensive data validation before storage.

#### 11. **Missing Backup Verification**

**Issue**: No verification that backups are complete and recoverable.
**Risk**: Backup corruption going undetected.
**Impact**: Data loss in disaster scenarios.
**Recommendation**: Implement backup validation and test recovery procedures.

#### 12. **No Audit Trail for Data Changes**

**Issue**: No tracking of who changed what data when.
**Risk**: Compliance violations and forensic investigation challenges.
**Impact**: Regulatory non-compliance and security incident response difficulties.
**Recommendation**: Implement comprehensive audit logging for all data operations.

### Implementation Recommendations

#### Immediate Fixes (Priority 1)

1. **Complete CRUD Operations**: Implement missing update and delete functionality
2. **Add Data Validation**: Validate all data before Firestore operations
3. **Implement Error Sanitization**: Clean error messages before client return
4. **Add Connection Pooling**: Optimize Firestore client management

#### Short-term Improvements (Priority 2)

1. **Implement Caching**: Add intelligent caching layer
2. **Add Batch Operations**: Support bulk API key operations
3. **Enhance Security Rules**: Implement field-level Firestore security
4. **Add Concurrent Modification Handling**: Implement optimistic locking

#### Long-term Enhancements (Priority 3)

1. **Key Rotation System**: Design and implement master key rotation
2. **HSM Integration**: Move to hardware security modules
3. **Multi-region Deployment**: Implement global Firestore distribution
4. **Advanced Monitoring**: Real-time performance and security monitoring

### Testing Requirements

1. **Load Testing**: Validate performance under concurrent operations
2. **Disaster Recovery Testing**: Verify backup and restore procedures
3. **Security Testing**: Penetration testing of Firestore integration
4. **Data Integrity Testing**: Validate encryption/decryption cycles
5. **Compliance Testing**: Verify SOC 2 and GDPR requirements

### Monitoring and Alerting Gaps

1. **Performance Metrics**: Missing operation latency and throughput monitoring
2. **Error Rate Tracking**: No automated error rate alerting
3. **Security Event Detection**: Missing suspicious activity detection
4. **Capacity Planning**: No proactive storage and query monitoring
5. **Cost Optimization**: Missing Firestore usage and cost tracking

## Future Enhancements

1. **Multi-Region Support**: Firestore multi-region deployments
2. **Advanced Indexing**: Custom indexes for complex queries
3. **Real-time Updates**: Firestore real-time listeners
4. **Batch Operations**: Optimized bulk API key operations
5. **Advanced Security**: Field-level encryption capabilities
