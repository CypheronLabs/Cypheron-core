// Integration tests for hybrid encryption system

use crate::security::auth::{
    HybridEncryption, VersionedEncryptedData, EncryptionVersion,
    PostQuantumEncryption, AuthError
};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_v1_to_v2_migration_simulation() {
        let test_password = "test".repeat(8); // 32-character password
        
        // Step 1: Simulate existing V1 encrypted API keys
        let legacy_encryption = PostQuantumEncryption::from_password(&test_password).unwrap();
        let api_keys = [
            b"pq_test_old_key_1234567890",
            b"pq_prod_legacy_abcdef1234", 
            b"pq_dev_migration_test_key",
        ];

        let mut v1_encrypted_keys = Vec::new();
        for key in &api_keys {
            let encrypted = legacy_encryption.encrypt(key).unwrap();
            let v1_data = VersionedEncryptedData {
                version: EncryptionVersion::V1AES256 as u8,
                data: encrypted,
            };
            v1_encrypted_keys.push(v1_data);
        }

        // Step 2: Create hybrid encryption with legacy support
        let hybrid_encryption = HybridEncryption::with_legacy_support(&test_password).unwrap();

        // Step 3: Verify all V1 keys can still be decrypted
        for (i, v1_encrypted) in v1_encrypted_keys.iter().enumerate() {
            let decrypted = hybrid_encryption.decrypt(v1_encrypted).unwrap();
            assert_eq!(&decrypted, api_keys[i]);
            assert_eq!(v1_encrypted.version, EncryptionVersion::V1AES256 as u8);
        }

        // Step 4: Encrypt new keys with V2 hybrid encryption
        let new_api_keys = [
            b"pq_test_new_hybrid_key_123",
            b"pq_prod_quantum_safe_key_456",
        ];

        let mut v2_encrypted_keys = Vec::new();
        for key in &new_api_keys {
            let encrypted = hybrid_encryption.encrypt(key).unwrap();
            assert_eq!(encrypted.version, EncryptionVersion::V2Hybrid as u8);
            v2_encrypted_keys.push(encrypted);
        }

        // Step 5: Verify all V2 keys decrypt correctly
        for (i, v2_encrypted) in v2_encrypted_keys.iter().enumerate() {
            let decrypted = hybrid_encryption.decrypt(v2_encrypted).unwrap();
            assert_eq!(&decrypted, new_api_keys[i]);
        }

        // Step 6: Verify mixed V1/V2 operation
        let mut all_encrypted = v1_encrypted_keys;
        all_encrypted.extend(v2_encrypted_keys);

        let mut all_expected = api_keys.to_vec();
        all_expected.extend(new_api_keys.iter());

        for (i, encrypted) in all_encrypted.iter().enumerate() {
            let decrypted = hybrid_encryption.decrypt(encrypted).unwrap();
            assert_eq!(&decrypted, all_expected[i]);
        }
    }

    #[test]
    fn test_api_key_encryption_workflow() {
        let hybrid_encryption = HybridEncryption::new();
        
        // Simulate typical API key management workflow
        let api_key_raw = "pq_test_1234567890abcdefghijklmnopqrstuv";
        
        // 1. Initial encryption (V2 hybrid)
        let encrypted_v2 = hybrid_encryption.encrypt(api_key_raw.as_bytes()).unwrap();
        assert_eq!(encrypted_v2.version, EncryptionVersion::V2Hybrid as u8);
        
        // 2. Storage simulation (serialize to JSON for database storage)
        let stored_data = serde_json::to_string(&encrypted_v2).unwrap();
        
        // 3. Retrieval simulation (deserialize from database)
        let retrieved_data: VersionedEncryptedData = serde_json::from_str(&stored_data).unwrap();
        
        // 4. Decryption for API key validation
        let decrypted_key = hybrid_encryption.decrypt(&retrieved_data).unwrap();
        let decrypted_str = String::from_utf8(decrypted_key).unwrap();
        
        assert_eq!(decrypted_str, api_key_raw);
    }

    #[test]
    fn test_multiple_encryption_instances() {
        // Test that different instances can decrypt each other's data
        let test_password = "shared".repeat(8); // 32 chars
        
        let encryption1 = HybridEncryption::with_legacy_support(&test_password).unwrap();
        let encryption2 = HybridEncryption::with_legacy_support(&test_password).unwrap();
        
        let api_key = b"pq_test_cross_instance_key";
        
        // Encrypt with instance 1
        let encrypted = encryption1.encrypt(api_key).unwrap();
        
        // Decrypt with instance 2
        let decrypted = encryption2.decrypt(&encrypted).unwrap();
        
        assert_eq!(&decrypted, api_key);
    }

    #[test]
    fn test_error_handling_scenarios() {
        let hybrid_encryption = HybridEncryption::new();
        
        // Test invalid version
        let invalid_version_data = VersionedEncryptedData {
            version: 99, // Invalid version
            data: vec![1, 2, 3],
        };
        
        // Should default to V1 and fail (no legacy support)
        let result = hybrid_encryption.decrypt(&invalid_version_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().error.contains("no_legacy_support"));
        
        // Test corrupted V2 data
        let corrupted_v2_data = VersionedEncryptedData {
            version: EncryptionVersion::V2Hybrid as u8,
            data: b"corrupted-json-data".to_vec(),
        };
        
        let result = hybrid_encryption.decrypt(&corrupted_v2_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().error.contains("deserialization_error"));
    }

    #[test]
    fn test_performance_characteristics() {
        let hybrid_encryption = HybridEncryption::new();
        let test_key = b"pq_performance_test_key_1234567890";
        
        // Test multiple encryption/decryption cycles
        let iterations = 100;
        let start_time = std::time::Instant::now();
        
        for _ in 0..iterations {
            let encrypted = hybrid_encryption.encrypt(test_key).unwrap();
            let _decrypted = hybrid_encryption.decrypt(&encrypted).unwrap();
        }
        
        let elapsed = start_time.elapsed();
        let avg_time_per_cycle = elapsed / iterations;
        
        // Should complete reasonably quickly (less than 10ms per cycle on most hardware)
        // This is a rough benchmark - actual performance will vary
        println!("Average time per encrypt/decrypt cycle: {:?}", avg_time_per_cycle);
        
        // Just ensure it completes successfully
        assert!(elapsed.as_secs() < 30); // Should complete 100 cycles in under 30 seconds
    }

    #[test]
    fn test_encryption_with_various_key_formats() {
        let hybrid_encryption = HybridEncryption::new();
        
        // Test various API key formats commonly used
        let test_keys = vec![
            // Short keys
            b"pk_test_123".to_vec(),
            // Standard Stripe-like format
            b"pk_test_1234567890123456".to_vec(),
            // Long keys
            b"pq_live_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec(),
            // Keys with special characters
            b"pq_test_key-with_underscores.and.dots".to_vec(),
            // Binary data simulation
            vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD],
        ];
        
        for (i, key) in test_keys.iter().enumerate() {
            let encrypted = hybrid_encryption.encrypt(key).unwrap();
            let decrypted = hybrid_encryption.decrypt(&encrypted).unwrap();
            
            assert_eq!(&decrypted, key, "Failed for key format {}", i);
            assert_eq!(encrypted.version, EncryptionVersion::V2Hybrid as u8);
        }
    }

    #[test]
    fn test_system_level_api_key_lifecycle() {
        // Comprehensive test simulating full API key lifecycle
        let password = "system".repeat(8); // 32 chars
        let hybrid_encryption = HybridEncryption::with_legacy_support(&password).unwrap();
        
        // 1. API Key Creation
        let new_api_key = b"pq_test_lifecycle_key_20250101";
        let encrypted_key = hybrid_encryption.encrypt(new_api_key).unwrap();
        
        // Verify it's using V2 encryption
        assert_eq!(encrypted_key.version, EncryptionVersion::V2Hybrid as u8);
        
        // 2. Storage (simulate database storage)
        let stored_json = serde_json::to_string(&encrypted_key).unwrap();
        
        // 3. Multiple retrievals and validations
        for _ in 0..10 {
            let retrieved: VersionedEncryptedData = serde_json::from_str(&stored_json).unwrap();
            let decrypted = hybrid_encryption.decrypt(&retrieved).unwrap();
            assert_eq!(&decrypted, new_api_key);
        }
        
        // 4. Key rotation simulation (old key still works, new key created)
        let rotated_key = b"pq_test_lifecycle_rotated_20250201";
        let encrypted_rotated = hybrid_encryption.encrypt(rotated_key).unwrap();
        
        // Both keys should work
        let decrypted_original = hybrid_encryption.decrypt(&encrypted_key).unwrap();
        let decrypted_rotated = hybrid_encryption.decrypt(&encrypted_rotated).unwrap();
        
        assert_eq!(&decrypted_original, new_api_key);
        assert_eq!(&decrypted_rotated, rotated_key);
        
        // 5. Legacy key support (simulate old key from V1)
        let legacy_encryption = PostQuantumEncryption::from_password(&password).unwrap();
        let legacy_key = b"pq_legacy_key_from_v1_system";
        let legacy_encrypted = legacy_encryption.encrypt(legacy_key).unwrap();
        
        let legacy_versioned = VersionedEncryptedData {
            version: EncryptionVersion::V1AES256 as u8,
            data: legacy_encrypted,
        };
        
        let decrypted_legacy = hybrid_encryption.decrypt(&legacy_versioned).unwrap();
        assert_eq!(&decrypted_legacy, legacy_key);
    }
}