#!/bin/bash

# Quick local test script for the cyberpunk status page
echo "🔥 Starting Cypheron API in LOCAL TEST MODE 🔥"
echo ""
echo "This will start the API with mock Firestore credentials"
echo "so you can test the cyberpunk status page locally!"
echo ""

# Create a temporary credentials file
mkdir -p /tmp/cypheron-test
cat > /tmp/cypheron-test/fake-credentials.json << 'EOF'
{
  "type": "service_account",
  "project_id": "test-project",
  "private_key_id": "fake-key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0fake-key-data\n-----END PRIVATE KEY-----\n",
  "client_email": "test@test-project.iam.gserviceaccount.com",
  "client_id": "123456789",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
EOF

echo "Starting API server..."
echo "📡 Status page will be available at: http://localhost:8080/status"
echo "🏥 Health check will be at: http://localhost:8080/health"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Run with fake credentials
docker run -p 8080:8080 \
  -v /tmp/cypheron-test/fake-credentials.json:/tmp/fake-credentials.json:ro \
  -e FIRESTORE_PROJECT_ID=test-project \
  -e PQ_MASTER_ADMIN_KEY=test-admin-key-12345 \
  -e PQ_ENCRYPTION_PASSWORD=test-encryption-key-12345 \
  -e PQ_TEST_API_KEY=test-api-key-for-testing \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/fake-credentials.json \
  cypheron-api:latest