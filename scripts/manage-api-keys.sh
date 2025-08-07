#!/bin/bash

# Cypheron Labs API Key Management Script
# For customer onboarding and key management

set -e

# Configuration
PROJECT_ID="cypheron-api"
SERVICE_NAME="cypheron-api"
REGION="us-central1"
SERVICE_URL="https://api.cypheronlabs.com"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${PURPLE}================================${NC}"
    echo -e "${PURPLE}  Cypheron Labs API Key Manager${NC}"
    echo -e "${PURPLE}  Post-Quantum Security Platform${NC}"
    echo -e "${PURPLE}================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check if gcloud is installed and authenticated
    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        print_error "Not authenticated with gcloud. Please run: gcloud auth login"
        exit 1
    fi
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        print_error "curl is not available. Please install curl."
        exit 1
    fi
    
    # Check if jq is available for JSON processing
    if ! command -v jq &> /dev/null; then
        print_warning "jq is not installed. JSON output will be raw."
        JQ_AVAILABLE=false
    else
        JQ_AVAILABLE=true
    fi
    
    print_success "Prerequisites check passed"
}

# Function to get service status
get_service_status() {
    print_info "Checking Cypheron API service status..."
    
    local status=$(gcloud run services describe $SERVICE_NAME --region=$REGION --format="value(status.conditions[0].status)" 2>/dev/null || echo "Unknown")
    
    if [ "$status" = "True" ]; then
        print_success "Service is running and ready"
        return 0
    else
        print_error "Service is not ready. Status: $status"
        return 1
    fi
}

# Function to create API key
create_api_key() {
    local customer_name="$1"
    local permissions="$2"
    local description="$3"
    local expires_days="$4"
    
    print_info "Creating API key for customer: $customer_name"
    
    # Get access token
    local access_token=$(gcloud auth print-access-token)
    if [ $? -ne 0 ]; then
        print_error "Failed to get access token"
        return 1
    fi
    
    # Get master admin key from Secret Manager
    print_info "Retrieving master admin key..."
    local master_key=$(gcloud secrets versions access latest --secret="pq-master-admin-key" 2>/dev/null)
    if [ $? -ne 0 ]; then
        print_error "Failed to retrieve master admin key from Secret Manager"
        return 1
    fi
    
    # Prepare JSON payload
    local json_payload=""
    if [ -n "$expires_days" ] && [ "$expires_days" -gt 0 ]; then
        local expires_at=$(date -d "+${expires_days} days" -u +"%Y-%m-%dT%H:%M:%SZ")
        json_payload=$(cat <<EOF
{
    "name": "$customer_name",
    "permissions": [$permissions],
    "description": "$description",
    "expires_at": "$expires_at"
}
EOF
)
    else
        json_payload=$(cat <<EOF
{
    "name": "$customer_name",
    "permissions": [$permissions],
    "description": "$description"
}
EOF
)
    fi
    
    print_info "Sending API key creation request..."
    
    # Make the API call
    local response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $access_token" \
        -H "x-api-key: $master_key" \
        -H "Content-Type: application/json" \
        -X POST \
        -d "$json_payload" \
        "$SERVICE_URL/admin/api-keys" 2>/dev/null)
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        print_success "API key created successfully!"
        echo -e "\n${CYAN}Customer API Key Details:${NC}"
        echo "=========================="
        
        if [ "$JQ_AVAILABLE" = true ]; then
            echo "$body" | jq -r '
                "Customer: " + .name,
                "API Key: " + .key,
                "Permissions: " + (.permissions | join(", ")),
                "Created: " + .created_at,
                ("Expires: " + (.expires_at // "Never")),
                "Description: " + .description
            '
        else
            echo "$body"
        fi
        
        # Extract and display the key prominently
        if [ "$JQ_AVAILABLE" = true ]; then
            local api_key=$(echo "$body" | jq -r '.key')
            echo -e "\n${GREEN}🔑 API Key: ${api_key}${NC}"
            echo -e "${YELLOW}⚠️  Save this key securely - it won't be shown again!${NC}\n"
        fi
        
        return 0
    else
        print_error "Failed to create API key. HTTP Code: $http_code"
        echo "Response: $body"
        return 1
    fi
}

# Function to list API keys
list_api_keys() {
    print_info "Retrieving API keys..."
    
    local access_token=$(gcloud auth print-access-token)
    local master_key=$(gcloud secrets versions access latest --secret="pq-master-admin-key" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        print_error "Failed to retrieve master admin key"
        return 1
    fi
    
    local response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $access_token" \
        -H "x-api-key: $master_key" \
        "$SERVICE_URL/admin/api-keys" 2>/dev/null)
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" = "200" ]; then
        print_success "API keys retrieved successfully!"
        echo -e "\n${CYAN}Active API Keys:${NC}"
        echo "================"
        
        if [ "$JQ_AVAILABLE" = true ]; then
            echo "$body" | jq -r '.keys[] | 
                "Name: " + .name + 
                " | Permissions: " + (.permissions | join(", ")) + 
                " | Created: " + .created_at + 
                " | Active: " + (.is_active | tostring)'
        else
            echo "$body"
        fi
    else
        print_error "Failed to retrieve API keys. HTTP Code: $http_code"
        echo "Response: $body"
        return 1
    fi
}

# Function to test API key
test_api_key() {
    local api_key="$1"
    
    if [ -z "$api_key" ]; then
        echo -n "Enter API key to test: "
        read -s api_key
        echo
    fi
    
    print_info "Testing API key..."
    
    # Test with health endpoint
    local response=$(curl -s -w "\n%{http_code}" \
        -H "x-api-key: $api_key" \
        "$SERVICE_URL/health" 2>/dev/null)
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" = "200" ]; then
        print_success "API key is valid and working!"
        if [ "$JQ_AVAILABLE" = true ]; then
            echo "$body" | jq .
        else
            echo "$body"
        fi
    else
        print_error "API key test failed. HTTP Code: $http_code"
        echo "Response: $body"
    fi
}

# Function to show usage
show_usage() {
    echo -e "${CYAN}Usage: $0 [COMMAND] [OPTIONS]${NC}\n"
    echo -e "${YELLOW}Commands:${NC}"
    echo "  create    Create a new API key for a customer"
    echo "  list      List all existing API keys"
    echo "  test      Test an API key"
    echo "  status    Check service status"
    echo "  help      Show this help message"
    echo
    echo -e "${YELLOW}Create API Key Options:${NC}"
    echo "  -n, --name NAME         Customer name (required)"
    echo "  -p, --permissions PERMS Permissions (default: \"read\")"
    echo "  -d, --description DESC  Description of the key"
    echo "  -e, --expires DAYS      Expiration in days (optional)"
    echo
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 create -n \"Acme Corp\" -d \"Production API access\""
    echo "  $0 create -n \"Test User\" -p \"read,write\" -e 30"
    echo "  $0 test abc123..."
    echo "  $0 list"
    echo "  $0 status"
}

# Main function
main() {
    print_header
    
    local command="$1"
    shift || true
    
    case "$command" in
        "create")
            check_prerequisites
            get_service_status || exit 1
            
            local customer_name=""
            local permissions="\"read\""
            local description=""
            local expires_days=""
            
            # Parse arguments
            while [[ $# -gt 0 ]]; do
                case $1 in
                    -n|--name)
                        customer_name="$2"
                        shift 2
                        ;;
                    -p|--permissions)
                        # Convert comma-separated to JSON array
                        permissions=$(echo "\"$2\"" | sed 's/,/","/g')
                        permissions="\"$permissions\""
                        shift 2
                        ;;
                    -d|--description)
                        description="$2"
                        shift 2
                        ;;
                    -e|--expires)
                        expires_days="$2"
                        shift 2
                        ;;
                    *)
                        print_error "Unknown option: $1"
                        show_usage
                        exit 1
                        ;;
                esac
            done
            
            if [ -z "$customer_name" ]; then
                print_error "Customer name is required"
                show_usage
                exit 1
            fi
            
            if [ -z "$description" ]; then
                description="API key for $customer_name"
            fi
            
            create_api_key "$customer_name" "$permissions" "$description" "$expires_days"
            ;;
            
        "list")
            check_prerequisites
            get_service_status || exit 1
            list_api_keys
            ;;
            
        "test")
            check_prerequisites
            get_service_status || exit 1
            test_api_key "$1"
            ;;
            
        "status")
            check_prerequisites
            get_service_status
            ;;
            
        "help"|"--help"|"-h")
            show_usage
            ;;
            
        "")
            print_error "No command specified"
            show_usage
            exit 1
            ;;
            
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"