use crate::error::AppError;
use axum::Json;
use serde_json::json;

pub async fn nist_compliance_info() -> Result<Json<serde_json::Value>, AppError> {
    let compliance_info = json!({
        "nist_compliance": {
            "version": "v0.2.0",
            "status": "FIPS Compliant",
            "standards": {
                "fips_203": {
                    "name": "Module-Lattice-Based Key-Encapsulation Mechanism Standard",
                    "algorithms": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
                    "status": "Implemented",
                    "endpoints": {
                        "ml_kem_512": {
                            "keygen": "/kem/ml-kem-512/keygen",
                            "encapsulate": "/kem/ml-kem-512/encapsulate",
                            "decapsulate": "/kem/ml-kem-512/decapsulate",
                            "info": "/kem/ml-kem-512/info"
                        },
                        "ml_kem_768": {
                            "keygen": "/kem/ml-kem-768/keygen",
                            "encapsulate": "/kem/ml-kem-768/encapsulate",
                            "decapsulate": "/kem/ml-kem-768/decapsulate",
                            "info": "/kem/ml-kem-768/info"
                        },
                        "ml_kem_1024": {
                            "keygen": "/kem/ml-kem-1024/keygen",
                            "encapsulate": "/kem/ml-kem-1024/encapsulate",
                            "decapsulate": "/kem/ml-kem-1024/decapsulate",
                            "info": "/kem/ml-kem-1024/info"
                        }
                    }
                },
                "fips_204": {
                    "name": "Module-Lattice-Based Digital Signature Standard",
                    "algorithms": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
                    "status": "Implemented",
                    "endpoints": {
                        "ml_dsa_44": {
                            "keygen": "/sig/ml-dsa-44/keygen",
                            "sign": "/sig/ml-dsa-44/sign",
                            "verify": "/sig/ml-dsa-44/verify"
                        },
                        "ml_dsa_65": {
                            "keygen": "/sig/ml-dsa-65/keygen",
                            "sign": "/sig/ml-dsa-65/sign",
                            "verify": "/sig/ml-dsa-65/verify"
                        },
                        "ml_dsa_87": {
                            "keygen": "/sig/ml-dsa-87/keygen",
                            "sign": "/sig/ml-dsa-87/sign",
                            "verify": "/sig/ml-dsa-87/verify"
                        }
                    }
                },
                "fips_205": {
                    "name": "Stateless Hash-Based Digital Signature Standard",
                    "algorithms": ["SLH-DSA-HARAKA-192F", "SLH-DSA-SHA2-256S", "SLH-DSA-SHAKE-128F"],
                    "status": "Implemented",
                    "endpoints": {
                        "slh_dsa_haraka_192f": {
                            "keygen": "/sig/slh-dsa-haraka-192f/keygen",
                            "sign": "/sig/slh-dsa-haraka-192f/sign",
                            "verify": "/sig/slh-dsa-haraka-192f/verify"
                        },
                        "slh_dsa_sha2_256s": {
                            "keygen": "/sig/slh-dsa-sha2-256s/keygen",
                            "sign": "/sig/slh-dsa-sha2-256s/sign",
                            "verify": "/sig/slh-dsa-sha2-256s/verify"
                        },
                        "slh_dsa_shake_128f": {
                            "keygen": "/sig/slh-dsa-shake-128f/keygen",
                            "sign": "/sig/slh-dsa-shake-128f/sign",
                            "verify": "/sig/slh-dsa-shake-128f/verify"
                        }
                    }
                }
            },
            "migration_guide": {
                "overview": "Cypheron API now supports NIST FIPS compliant algorithm names. Old names are deprecated but still supported for backward compatibility.",
                "kem_migrations": {
                    "kyber512": "ml-kem-512",
                    "kyber768": "ml-kem-768",
                    "kyber1024": "ml-kem-1024"
                },
                "signature_migrations": {
                    "dilithium2": "ml-dsa-44",
                    "dilithium3": "ml-dsa-65",
                    "dilithium5": "ml-dsa-87",
                    "haraka_192f": "slh-dsa-haraka-192f",
                    "sha2_256s": "slh-dsa-sha2-256s",
                    "shake_128f": "slh-dsa-shake-128f"
                },
                "timeline": {
                    "v0.2.0": "NIST compliant names introduced with deprecation warnings",
                    "v0.3.0": "Old names will show deprecation warnings in responses",
                    "v1.0.0": "Old names will be completely removed"
                }
            },
            "security_features": {
                "post_quantum_encryption": {
                    "algorithm": "ML-KEM-768 + ChaCha20-Poly1305",
                    "description": "API key storage uses post-quantum key encapsulation with authenticated encryption",
                    "status": "Active"
                },
                "constant_time_operations": {
                    "description": "All cryptographic operations use constant-time implementations to prevent timing attacks",
                    "status": "Active"
                },
                "secure_memory": {
                    "description": "Automatic memory zeroization for sensitive data using ZeroizeOnDrop",
                    "status": "Active"
                },
                "audit_logging": {
                    "description": "Comprehensive audit trail for all cryptographic operations",
                    "status": "Active"
                }
            }
        },
        "additional_algorithms": {
            "falcon": {
                "description": "NIST Round 3 finalist, pending standardization",
                "algorithms": ["Falcon-512", "Falcon-1024"],
                "endpoints": {
                    "falcon_512": {
                        "keygen": "/sig/falcon-512/keygen",
                        "sign": "/sig/falcon-512/sign",
                        "verify": "/sig/falcon-512/verify"
                    },
                    "falcon_1024": {
                        "keygen": "/sig/falcon-1024/keygen",
                        "sign": "/sig/falcon-1024/sign",
                        "verify": "/sig/falcon-1024/verify"
                    }
                }
            }
        },
        "hybrid_cryptography": {
            "description": "Post-quantum + classical cryptography for enhanced security",
            "algorithms": [
                "ECDSA P-256 + ML-DSA-44",
                "ECDSA P-256 + ML-DSA-65",
                "ECDSA P-256 + ML-DSA-87",
                "ECDSA P-256 + Falcon-512",
                "ECDSA P-256 + Falcon-1024"
            ],
            "endpoints": {
                "ecc_ml_dsa_44": "/hybrid/ecc-ml-dsa-44/sign",
                "ecc_ml_dsa_65": "/hybrid/ecc-ml-dsa-65/sign",
                "ecc_ml_dsa_87": "/hybrid/ecc-ml-dsa-87/sign",
                "ecc_falcon_512": "/hybrid/ecc-falcon-512/sign",
                "ecc_falcon_1024": "/hybrid/ecc-falcon-1024/sign"
            }
        },
        "examples": {
            "ml_kem_512_usage": {
                "description": "Example usage of NIST FIPS 203 compliant ML-KEM-512",
                "endpoints": {
                    "1_generate_keypair": {
                        "method": "POST",
                        "url": "/kem/ml-kem-512/keygen",
                        "response": {
                            "pk": "base64_encoded_public_key",
                            "sk": "base64_encoded_secret_key",
                            "format": "base64"
                        }
                    },
                    "2_encapsulate": {
                        "method": "POST",
                        "url": "/kem/ml-kem-512/encapsulate",
                        "payload": {
                            "pk": "base64_encoded_public_key",
                            "format": "base64"
                        },
                        "response": {
                            "ct": "base64_encoded_ciphertext",
                            "ss": "base64_encoded_shared_secret",
                            "format": "base64"
                        }
                    },
                    "3_decapsulate": {
                        "method": "POST",
                        "url": "/kem/ml-kem-512/decapsulate",
                        "payload": {
                            "ct": "base64_encoded_ciphertext",
                            "sk": "base64_encoded_secret_key",
                            "format": "base64"
                        },
                        "response": {
                            "ss": "base64_encoded_shared_secret",
                            "format": "base64"
                        }
                    }
                }
            },
            "ml_dsa_44_usage": {
                "description": "Example usage of NIST FIPS 204 compliant ML-DSA-44",
                "endpoints": {
                    "1_generate_keypair": {
                        "method": "POST",
                        "url": "/sig/ml-dsa-44/keygen",
                        "response": {
                            "pk": "base64_encoded_public_key",
                            "sk": "base64_encoded_secret_key"
                        }
                    },
                    "2_sign": {
                        "method": "POST",
                        "url": "/sig/ml-dsa-44/sign",
                        "payload": {
                            "message": "Hello, NIST FIPS 204!",
                            "sk": "base64_encoded_secret_key"
                        },
                        "response": {
                            "signature": "base64_encoded_signature"
                        }
                    },
                    "3_verify": {
                        "method": "POST",
                        "url": "/sig/ml-dsa-44/verify",
                        "payload": {
                            "message": "Hello, NIST FIPS 204!",
                            "signature": "base64_encoded_signature",
                            "pk": "base64_encoded_public_key"
                        },
                        "response": {
                            "valid": true
                        }
                    }
                }
            }
        }
    });

    Ok(Json(compliance_info))
}

pub async fn deprecation_warnings() -> Result<Json<serde_json::Value>, AppError> {
    let warnings = json!({
        "deprecation_warnings": {
            "message": "The following algorithm names are deprecated and will be removed in v1.0.0",
            "deprecated_algorithms": {
                "kem": {
                    "kyber512": {
                        "deprecated_since": "v0.2.0",
                        "replacement": "ml-kem-512",
                        "removal_version": "v1.0.0",
                        "migration_url": "/nist/compliance"
                    },
                    "kyber768": {
                        "deprecated_since": "v0.2.0",
                        "replacement": "ml-kem-768",
                        "removal_version": "v1.0.0",
                        "migration_url": "/nist/compliance"
                    },
                    "kyber1024": {
                        "deprecated_since": "v0.2.0",
                        "replacement": "ml-kem-1024",
                        "removal_version": "v1.0.0",
                        "migration_url": "/nist/compliance"
                    }
                },
                "signatures": {
                    "dilithium2": {
                        "deprecated_since": "v0.2.0",
                        "replacement": "ml-dsa-44",
                        "removal_version": "v1.0.0",
                        "migration_url": "/nist/compliance"
                    },
                    "dilithium3": {
                        "deprecated_since": "v0.2.0",
                        "replacement": "ml-dsa-65",
                        "removal_version": "v1.0.0",
                        "migration_url": "/nist/compliance"
                    },
                    "dilithium5": {
                        "deprecated_since": "v0.2.0",
                        "replacement": "ml-dsa-87",
                        "removal_version": "v1.0.0",
                        "migration_url": "/nist/compliance"
                    },
                    "haraka_192f": {
                        "deprecated_since": "v0.2.0",
                        "replacement": "slh-dsa-haraka-192f",
                        "removal_version": "v1.0.0",
                        "migration_url": "/nist/compliance"
                    },
                    "sha2_256s": {
                        "deprecated_since": "v0.2.0",
                        "replacement": "slh-dsa-sha2-256s",
                        "removal_version": "v1.0.0",
                        "migration_url": "/nist/compliance"
                    },
                    "shake_128f": {
                        "deprecated_since": "v0.2.0",
                        "replacement": "slh-dsa-shake-128f",
                        "removal_version": "v1.0.0",
                        "migration_url": "/nist/compliance"
                    }
                }
            },
            "migration_checklist": [
                "1. Update client code to use NIST compliant algorithm names",
                "2. Test all endpoints with new naming conventions",
                "3. Update documentation and configuration files",
                "4. Plan for complete migration before v1.0.0 release",
                "5. Monitor application logs for deprecation warnings"
            ]
        }
    });

    Ok(Json(warnings))
}
