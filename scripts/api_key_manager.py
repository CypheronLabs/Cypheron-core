#!/usr/bin/env python3
"""
Cypheron Labs API Key Management Tool
For customer onboarding and key management
"""

import json
import requests
import subprocess
import sys
import argparse
from datetime import datetime, timedelta
from typing import Optional, List
import os

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

class CypheronAPIManager:
    def __init__(self):
        self.project_id = "cypheron-api"
        self.service_name = "cypheron-api"
        self.region = "us-central1"
        self.service_url = "https://api.cypheronlabs.com"
        
    def print_header(self):
        print(f"{Colors.PURPLE}================================{Colors.NC}")
        print(f"{Colors.PURPLE}  Cypheron Labs API Key Manager{Colors.NC}")
        print(f"{Colors.PURPLE}  Post-Quantum Security Platform{Colors.NC}")
        print(f"{Colors.PURPLE}================================{Colors.NC}\n")
        
    def print_success(self, message: str):
        print(f"{Colors.GREEN}✅ {message}{Colors.NC}")
        
    def print_error(self, message: str):
        print(f"{Colors.RED}❌ {message}{Colors.NC}")
        
    def print_warning(self, message: str):
        print(f"{Colors.YELLOW}⚠️  {message}{Colors.NC}")
        
    def print_info(self, message: str):
        print(f"{Colors.BLUE}ℹ️  {message}{Colors.NC}")
        
    def get_access_token(self) -> Optional[str]:
        """Get Google Cloud access token"""
        try:
            result = subprocess.run(
                ['gcloud', 'auth', 'print-access-token'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.print_error("Failed to get access token. Make sure you're authenticated with gcloud.")
            return None
            
    def get_master_admin_key(self) -> Optional[str]:
        """Get master admin key from Secret Manager"""
        try:
            result = subprocess.run([
                'gcloud', 'secrets', 'versions', 'access', 'latest',
                '--secret=pq-master-admin-key'
            ], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.print_error("Failed to retrieve master admin key from Secret Manager")
            return None
            
    def check_service_status(self) -> bool:
        """Check if the Cypheron API service is running"""
        self.print_info("Checking Cypheron API service status...")
        try:
            result = subprocess.run([
                'gcloud', 'run', 'services', 'describe', self.service_name,
                '--region', self.region,
                '--format', 'value(status.conditions[0].status)'
            ], capture_output=True, text=True, check=True)
            
            status = result.stdout.strip()
            if status == "True":
                self.print_success("Service is running and ready")
                return True
            else:
                self.print_error(f"Service is not ready. Status: {status}")
                return False
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.print_error("Failed to check service status")
            return False
            
    def create_api_key(self, name: str, permissions: List[str] = None, 
                      description: str = None, expires_days: int = None) -> bool:
        """Create a new API key"""
        if permissions is None:
            permissions = ["read"]
            
        if description is None:
            description = f"API key for {name}"
            
        self.print_info(f"Creating API key for customer: {name}")
        
        # Get authentication tokens
        access_token = self.get_access_token()
        if not access_token:
            return False
            
        master_key = self.get_master_admin_key()
        if not master_key:
            return False
            
        # Prepare payload
        payload = {
            "name": name,
            "permissions": permissions,
            "description": description
        }
        
        if expires_days and expires_days > 0:
            expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat() + "Z"
            payload["expires_at"] = expires_at
            
        headers = {
            "Authorization": f"Bearer {access_token}",
            "x-api-key": master_key,
            "Content-Type": "application/json"
        }
        
        try:
            self.print_info("Sending API key creation request...")
            response = requests.post(
                f"{self.service_url}/admin/api-keys",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                self.print_success("API key created successfully!")
                data = response.json()
                
                print(f"\n{Colors.CYAN}Customer API Key Details:{Colors.NC}")
                print("==========================")
                print(f"Customer: {data['name']}")
                print(f"API Key: {data['key']}")
                print(f"Permissions: {', '.join(data['permissions'])}")
                print(f"Created: {data['created_at']}")
                print(f"Expires: {data.get('expires_at', 'Never')}")
                print(f"Description: {data['description']}")
                
                print(f"\n{Colors.GREEN}🔑 API Key: {data['key']}{Colors.NC}")
                print(f"{Colors.YELLOW}⚠️  Save this key securely - it won't be shown again!{Colors.NC}\n")
                
                return True
            else:
                self.print_error(f"Failed to create API key. Status: {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"Error: {error_data}")
                except:
                    print(f"Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.print_error(f"Request failed: {e}")
            return False
            
    def list_api_keys(self) -> bool:
        """List all API keys"""
        self.print_info("Retrieving API keys...")
        
        access_token = self.get_access_token()
        if not access_token:
            return False
            
        master_key = self.get_master_admin_key()
        if not master_key:
            return False
            
        headers = {
            "Authorization": f"Bearer {access_token}",
            "x-api-key": master_key
        }
        
        try:
            response = requests.get(
                f"{self.service_url}/admin/api-keys",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                self.print_success("API keys retrieved successfully!")
                data = response.json()
                
                print(f"\n{Colors.CYAN}Active API Keys:{Colors.NC}")
                print("================")
                
                if "keys" in data:
                    for key_info in data["keys"]:
                        print(f"Name: {key_info['name']}")
                        print(f"  Permissions: {', '.join(key_info['permissions'])}")
                        print(f"  Created: {key_info['created_at']}")
                        print(f"  Active: {key_info['is_active']}")
                        print(f"  Usage Count: {key_info.get('usage_count', 0)}")
                        if key_info.get('expires_at'):
                            print(f"  Expires: {key_info['expires_at']}")
                        print()
                else:
                    print("No API keys found.")
                    
                return True
            else:
                self.print_error(f"Failed to retrieve API keys. Status: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.print_error(f"Request failed: {e}")
            return False
            
    def test_api_key(self, api_key: str = None) -> bool:
        """Test an API key"""
        if not api_key:
            api_key = input("Enter API key to test: ").strip()
            
        self.print_info("Testing API key...")
        
        headers = {
            "x-api-key": api_key
        }
        
        try:
            response = requests.get(
                f"{self.service_url}/health",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                self.print_success("API key is valid and working!")
                try:
                    data = response.json()
                    print(json.dumps(data, indent=2))
                except:
                    print(response.text)
                return True
            else:
                self.print_error(f"API key test failed. Status: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.print_error(f"Request failed: {e}")
            return False

def main():
    manager = CypheronAPIManager()
    manager.print_header()
    
    parser = argparse.ArgumentParser(description="Cypheron Labs API Key Manager")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new API key')
    create_parser.add_argument('-n', '--name', required=True, help='Customer name')
    create_parser.add_argument('-p', '--permissions', help='Permissions (comma-separated)', default='read')
    create_parser.add_argument('-d', '--description', help='Description of the key')
    create_parser.add_argument('-e', '--expires', type=int, help='Expiration in days')
    
    # List command
    subparsers.add_parser('list', help='List all API keys')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test an API key')
    test_parser.add_argument('api_key', nargs='?', help='API key to test')
    
    # Status command
    subparsers.add_parser('status', help='Check service status')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
        
    if args.command == 'create':
        permissions = [p.strip() for p in args.permissions.split(',')]
        success = manager.create_api_key(
            name=args.name,
            permissions=permissions,
            description=args.description,
            expires_days=args.expires
        )
        sys.exit(0 if success else 1)
        
    elif args.command == 'list':
        if not manager.check_service_status():
            sys.exit(1)
        success = manager.list_api_keys()
        sys.exit(0 if success else 1)
        
    elif args.command == 'test':
        if not manager.check_service_status():
            sys.exit(1)
        success = manager.test_api_key(args.api_key)
        sys.exit(0 if success else 1)
        
    elif args.command == 'status':
        success = manager.check_service_status()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()