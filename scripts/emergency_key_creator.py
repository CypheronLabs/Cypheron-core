#!/usr/bin/env python3
"""
Emergency API Key Creator for Cypheron Labs
Creates API keys directly in Firestore when API endpoints are unavailable
"""

import argparse
import hashlib
import secrets
import json
from datetime import datetime, timedelta
from typing import List
import subprocess
import sys

class EmergencyKeyCreator:
    def __init__(self, project_id: str = "cypheron-api"):
        self.project_id = project_id
        self.collection_name = "api_keys"
        
    def generate_api_key(self) -> str:
        """Generate a secure 64-character hex API key"""
        return secrets.token_hex(32)
        
    def hash_key(self, api_key: str) -> str:
        """Generate SHA-256 hash for key lookup"""
        return hashlib.sha256(api_key.encode()).hexdigest()
        
    def create_key_document(self, name: str, api_key: str, permissions: List[str],
                          description: str = None, expires_days: int = None) -> dict:
        """Create the Firestore document structure"""
        now = datetime.utcnow()
        
        doc = {
            "name": name,
            "key_hash": self.hash_key(api_key),
            "permissions": permissions,
            "description": description or f"Emergency API key for {name}",
            "created_at": now.isoformat() + "Z",
            "is_active": True,
            "usage_count": 0,
            "last_used_at": None,
            # Note: In production, the actual key would be encrypted
            # For emergency use, we're storing a flag to indicate this is unencrypted
            "emergency_created": True,
            "encrypted_key": api_key  # In production this would be encrypted
        }
        
        if expires_days:
            expires_at = now + timedelta(days=expires_days)
            doc["expires_at"] = expires_at.isoformat() + "Z"
            
        return doc
        
    def add_to_firestore(self, doc_id: str, document: dict) -> bool:
        """Add document to Firestore using gcloud CLI"""
        try:
            # Convert document to JSON string
            doc_json = json.dumps(document)
            
            # Use gcloud to add document
            cmd = [
                "gcloud", "firestore", "documents", "create",
                f"projects/{self.project_id}/databases/(default)/documents/{self.collection_name}/{doc_id}",
                f"--data={doc_json}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Error adding to Firestore: {e}")
            print(f"stderr: {e.stderr}")
            return False
            
    def create_emergency_key(self, name: str, permissions: List[str],
                           description: str = None, expires_days: int = None) -> tuple[str, bool]:
        """Create an emergency API key"""
        print(f"🚨 Creating EMERGENCY API key for: {name}")
        print("⚠️  This bypasses normal encryption - use only when API endpoints are down")
        
        # Generate API key
        api_key = self.generate_api_key()
        key_hash = self.hash_key(api_key)
        
        # Create document
        document = self.create_key_document(name, api_key, permissions, description, expires_days)
        
        # Use hash as document ID for consistent lookup
        doc_id = key_hash
        
        # Add to Firestore
        success = self.add_to_firestore(doc_id, document)
        
        if success:
            print("✅ Emergency API key created successfully!")
            print(f"\n🔑 API Key: {api_key}")
            print(f"📝 Customer: {name}")
            print(f"🛡️  Permissions: {', '.join(permissions)}")
            if expires_days:
                expires_date = datetime.utcnow() + timedelta(days=expires_days)
                print(f"⏰ Expires: {expires_date.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            print(f"📄 Description: {document['description']}")
            
            print(f"\n⚠️  IMPORTANT SECURITY NOTES:")
            print("1. This key was created without proper post-quantum encryption")
            print("2. Recreate this key using normal API endpoints when service is restored")
            print("3. This is for emergency use only")
            print("4. Monitor this key closely and replace it ASAP")
            
            return api_key, True
        else:
            print("❌ Failed to create emergency API key")
            return None, False

def main():
    parser = argparse.ArgumentParser(description="Emergency API Key Creator for Cypheron Labs")
    parser.add_argument("--customer", required=True, help="Customer name")
    parser.add_argument("--permissions", default="read", help="Permissions (comma-separated)")
    parser.add_argument("--description", help="Key description")
    parser.add_argument("--expires", type=int, help="Expiration in days")
    parser.add_argument("--project", default="cypheron-api", help="Firestore project ID")
    
    args = parser.parse_args()
    
    # Parse permissions
    permissions = [p.strip() for p in args.permissions.split(",")]
    
    # Validate permissions
    valid_permissions = ["read", "write", "admin"]
    for perm in permissions:
        if perm not in valid_permissions:
            print(f"❌ Invalid permission: {perm}")
            print(f"Valid permissions: {', '.join(valid_permissions)}")
            sys.exit(1)
    
    print("🚨 EMERGENCY API KEY CREATION TOOL 🚨")
    print("=====================================")
    print("⚠️  WARNING: This tool bypasses normal security measures")
    print("⚠️  Use only when regular API endpoints are unavailable")
    print("⚠️  Replace keys created with this tool as soon as service is restored")
    print()
    
    # Confirm with user
    response = input("Do you want to continue? (yes/no): ").strip().lower()
    if response != "yes":
        print("Operation cancelled.")
        sys.exit(0)
    
    # Create the key
    creator = EmergencyKeyCreator(args.project)
    api_key, success = creator.create_emergency_key(
        name=args.customer,
        permissions=permissions,
        description=args.description,
        expires_days=args.expires
    )
    
    if success:
        print(f"\n💾 Save this information securely:")
        print(f"Customer: {args.customer}")
        print(f"API Key: {api_key}")
        print(f"Created: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
        
        # Test the key
        print(f"\n🧪 To test this key:")
        print(f"curl -H 'x-api-key: {api_key}' https://api.cypheronlabs.com/health")
        
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()