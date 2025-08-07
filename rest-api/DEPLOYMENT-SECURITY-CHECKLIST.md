# Cypheron API Deployment Security Checklist

## Critical Security Requirements

### 1. Master Password & Encryption Configuration

**REQUIRED** - These must be set for secure operation:

```bash
# Post-quantum encryption password (minimum 32 characters)
export PQ_ENCRYPTION_PASSWORD="your-secure-master-password-at-least-32-chars-long"

# Encryption salt (minimum 16 bytes, base64 encoded recommended)
export PQ_ENCRYPTION_SALT="your-cryptographically-secure-salt-16-bytes-minimum"

# Master admin key for administrative operations
export PQ_MASTER_ADMIN_KEY="your-secure-admin-key"
```

### 2. Database Configuration

**PostgreSQL Connection:**
```bash
# Option 1: Full DATABASE_URL
export DATABASE_URL="postgresql://username:password@hostname:5432/database_name"

# Option 2: Individual components
export DB_HOST="localhost"
export DB_PORT="5432"
export DB_USER="cypheron_user"
export DB_PASSWORD="secure-database-password"
export DB_NAME="cypheron_prod"

# Connection Pool Settings (optional)
export DB_MAX_CONNECTIONS="20"
export DB_MIN_CONNECTIONS="5"
export DB_CONNECT_TIMEOUT="30"
export DB_IDLE_TIMEOUT="600"
export DB_MAX_LIFETIME="1800"
```

**Legacy Firestore (for migration only):**
```bash
export GOOGLE_CLOUD_PROJECT_ID="your-gcp-project-id"
export FIRESTORE_COLLECTION="api_keys"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
```

### 3. Security Controls Configuration

**Enable all SOC 2 compliance controls:**
```bash
export SECURITY_VULNERABILITY_SCANNING_ENABLED="true"
export SECURITY_BACKUP_PROCEDURES_ACTIVE="true"
```

**Rate Limiting:**
```bash
export RATE_LIMIT_REQUESTS_PER_MINUTE="60"
```

## Pre-Migration Security Verification

### ✅ Critical Security Fixes Applied

1. **Master Password Security**
   - ✅ Removed hardcoded fallback password
   - ✅ Enforced minimum 32-character password requirement
   - ✅ Required unique salt from environment variable
   - ✅ Added password strength validation

2. **API Key Validation**
   - ✅ Comprehensive validation pipeline implemented
   - ✅ Expiration checking enabled
   - ✅ Active status validation
   - ✅ Usage count tracking

3. **Error Message Sanitization**
   - ✅ All internal errors sanitized before client return
   - ✅ Sensitive information removed from error messages
   - ✅ Detailed errors logged internally only

4. **Repository Pattern**
   - ✅ Interface abstraction for database backends
   - ✅ PostgreSQL repository with transaction support
   - ✅ Legacy Firestore repository for backward compatibility

### ✅ Infrastructure Improvements

1. **Database Architecture**
   - ✅ PostgreSQL schema with comprehensive security features
   - ✅ Connection pooling with optimized settings
   - ✅ Transaction support for atomicity
   - ✅ Audit logging and analytics tables

2. **Migration Tooling**
   - ✅ Firestore to PostgreSQL migration utility
   - ✅ Data validation and integrity checking
   - ✅ Dry-run capability for testing

3. **Compliance Controls**
   - ✅ SOC 2 security controls enabled by default
   - ✅ Vulnerability scanning configuration
   - ✅ Backup procedures activation

## Migration Process

### Phase 1: Environment Setup (CRITICAL)

1. **Set all required environment variables**
2. **Test PostgreSQL connectivity**
3. **Verify encryption configuration**

```bash
# Test database connection
cargo run --bin migration-tool -- --dry-run

# Verify encryption
echo "Testing encryption..." | openssl rand -base64 32
```

### Phase 2: Schema Deployment

```bash
# Apply PostgreSQL schema
psql -d $DATABASE_URL -f db/schema.sql

# Verify schema
psql -d $DATABASE_URL -c "\dt"
```

### Phase 3: Data Migration

```bash
# Dry run first
cargo run --bin migration-tool -- --dry-run

# Execute migration
cargo run --bin migration-tool

# Validate migration
cargo run --bin migration-tool -- --validate
```

### Phase 4: Security Validation

```bash
# Check compliance controls
curl -H "Authorization: Bearer $PQ_MASTER_ADMIN_KEY" \
     https://your-api/admin/compliance/status

# Verify error sanitization
curl https://your-api/invalid-endpoint

# Test rate limiting
for i in {1..65}; do curl https://your-api/health; done
```

## Security Best Practices

### 1. Environment Variable Security

- **Never commit secrets to version control**
- **Use secure secret management (GCP Secret Manager, AWS Secrets Manager)**
- **Rotate passwords regularly**
- **Monitor for environment variable leaks**

### 2. Database Security

- **Enable SSL/TLS for database connections**
- **Use strong passwords for database users**
- **Implement network-level access controls**
- **Regular backup and restore testing**

### 3. Monitoring and Alerting

```bash
# Set up monitoring for:
# - Failed authentication attempts
# - Rate limit violations
# - Database connection failures
# - Encryption/decryption errors
```

### 4. Incident Response

```bash
# Prepare for security incidents:
# - Log aggregation and analysis
# - Automated alerting
# - Emergency key rotation procedures
# - Backup restoration procedures
```

## Post-Migration Validation

### ✅ Functional Tests

1. **API Key Operations**
   - Create new API key
   - Validate existing API key
   - Update API key permissions
   - Delete API key

2. **Authentication & Authorization**
   - Valid API key acceptance
   - Invalid API key rejection
   - Permission enforcement
   - Rate limiting

3. **Data Integrity**
   - Encryption/decryption cycles
   - Database transaction rollback
   - Audit log accuracy

### ✅ Security Tests

1. **Error Handling**
   - No sensitive information in error messages
   - Proper HTTP status codes
   - Consistent error format

2. **Input Validation**
   - SQL injection prevention
   - XSS protection
   - Parameter tampering resistance

3. **Compliance**
   - Audit trail completeness
   - Data retention policies
   - Privacy controls

## Emergency Procedures

### Key Compromise Response

```bash
# 1. Disable compromised key
export COMPROMISED_KEY_HASH="sha256-hash-of-key"
psql -d $DATABASE_URL -c "UPDATE api_keys SET is_active = false WHERE key_hash = '$COMPROMISED_KEY_HASH';"

# 2. Rotate master password
# Generate new password and salt
openssl rand -base64 48
openssl rand -base64 24

# 3. Re-encrypt all stored keys
# (This requires implementing key rotation feature)
```

### Database Recovery

```bash
# 1. Stop API service
systemctl stop cypheron-api

# 2. Restore from backup
psql -d $DATABASE_URL < backup.sql

# 3. Verify data integrity
cargo run --bin migration-tool -- --validate

# 4. Restart service
systemctl start cypheron-api
```

## Compliance Checklist

### SOC 2 Requirements

- [x] **Security (CC6.0)**: Access controls, authentication, authorization
- [x] **Availability (CC7.0)**: System monitoring, error handling
- [x] **Processing Integrity (CC8.0)**: Input validation, data accuracy
- [x] **Confidentiality (CC9.0)**: Data encryption, access restrictions
- [x] **Privacy (P1.0)**: Data minimization, consent management

### GDPR Compliance

- [x] **Data Protection**: Encryption at rest and in transit
- [x] **Privacy by Design**: Pseudonymization, data minimization
- [x] **Right to be Forgotten**: Data deletion procedures
- [x] **Data Portability**: Export functionality
- [x] **Breach Notification**: Incident response procedures

## Support and Troubleshooting

### Common Issues

1. **Environment Variables Not Set**
   - Error: "PQ_ENCRYPTION_PASSWORD environment variable is required"
   - Solution: Set all required environment variables

2. **Database Connection Failures**
   - Error: "Database health check failed"
   - Solution: Verify DATABASE_URL and network connectivity

3. **Migration Failures**
   - Error: "Failed to decrypt stored key"
   - Solution: Ensure consistent encryption configuration

### Getting Help

- Review logs: `journalctl -u cypheron-api -f`
- Check configuration: `env | grep -E "(PQ_|DB_|SECURITY_)"`
- Validate schema: `psql -d $DATABASE_URL -c "\d+ api_keys"`

---

**⚠️ SECURITY NOTICE:** This checklist addresses the critical security vulnerabilities identified in the original Firestore implementation. All security fixes must be verified before production deployment.