#!/usr/bin/env python3
"""
Simple script to create a test API key directly in Firestore for immediate testing
"""

import hashlib
import secrets
import json
from datetime import datetime
import subprocess

def generate_api_key():
    """Generate a secure 64-character hex API key"""
    return secrets.token_hex(32)

def hash_key(api_key):
    """Generate SHA-256 hash for key lookup"""
    return hashlib.sha256(api_key.encode()).hexdigest()

def main():
    # Generate API key
    api_key = generate_api_key()
    key_hash = hash_key(api_key)
    
    print(f"Generated API Key: {api_key}")
    print(f"Key Hash: {key_hash}")
    
    # Create document structure (simplified for testing)
    doc = {
        "name": "Test Customer - Direct Creation",
        "key_hash": key_hash,
        "permissions": ["read"],
        "description": "Test key created directly for debugging",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "is_active": True,
        "usage_count": 0,
        "last_used_at": None,
        "emergency_created": True
    }
    
    print(f"\nDocument to create:")
    print(json.dumps(doc, indent=2))
    
    print(f"\nTo test this key:")
    print(f"curl -H 'x-api-key: {api_key}' https://api.cypheronlabs.com/health")
    
    print(f"\nFirestore document ID: {key_hash}")
    print(f"Collection: api_keys")

if __name__ == "__main__":
    main()