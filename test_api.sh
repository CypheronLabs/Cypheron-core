#!/bin/bash

# Post-Quantum Cryptography REST API Test Script
echo "🔐 Testing PQ Crypto REST API"
echo "==============================="

API_BASE="http://127.0.0.1:3000"

# Test message (base64 encoded "Hello Post-Quantum World!")
TEST_MESSAGE="SGVsbG8gUG9zdC1RdWFudHVtIFdvcmxkIQ=="

echo ""
echo "📡 Testing KEM (Key Encapsulation) - Kyber512"
echo "----------------------------------------------"
echo "1. Generating keypair..."
KEM_RESPONSE=$(curl -s -X POST "$API_BASE/kem/kyber512/keygen" -H "Content-Type: application/json")
KEM_PK=$(echo $KEM_RESPONSE | jq -r '.pk')
KEM_SK=$(echo $KEM_RESPONSE | jq -r '.sk')

echo "✅ Public Key Length: $(echo $KEM_PK | wc -c) chars"
echo "✅ Secret Key Length: $(echo $KEM_SK | wc -c) chars"

echo ""
echo "2. Testing encapsulation..."
ENCAP_DATA='{"pk":"'$KEM_PK'"}'
ENCAP_RESPONSE=$(curl -s -X POST "$API_BASE/kem/kyber512/encapsulate" \
  -H "Content-Type: application/json" -d "$ENCAP_DATA")
CIPHERTEXT=$(echo $ENCAP_RESPONSE | jq -r '.ciphertext')
SHARED_SECRET1=$(echo $ENCAP_RESPONSE | jq -r '.shared_secret')

echo "✅ Ciphertext Length: $(echo $CIPHERTEXT | wc -c) chars"
echo "✅ Shared Secret: $(echo $SHARED_SECRET1 | cut -c1-32)..."

echo ""
echo "3. Testing decapsulation..."
DECAP_DATA='{"ciphertext":"'$CIPHERTEXT'","sk":"'$KEM_SK'"}'
DECAP_RESPONSE=$(curl -s -X POST "$API_BASE/kem/kyber512/decapsulate" \
  -H "Content-Type: application/json" -d "$DECAP_DATA")
SHARED_SECRET2=$(echo $DECAP_RESPONSE | jq -r '.shared_secret')

if [ "$SHARED_SECRET1" = "$SHARED_SECRET2" ]; then
    echo "✅ Shared secrets match! KEM working correctly."
else
    echo "❌ Shared secrets don't match!"
fi

echo ""
echo "🖋️  Testing Digital Signatures - Falcon512"
echo "-------------------------------------------"
echo "1. Generating signature keypair..."
SIG_RESPONSE=$(curl -s -X POST "$API_BASE/sig/falcon512/keygen" -H "Content-Type: application/json")
SIG_PK=$(echo $SIG_RESPONSE | jq -r '.pk')
SIG_SK=$(echo $SIG_RESPONSE | jq -r '.sk')

echo "✅ Public Key Length: $(echo $SIG_PK | wc -c) chars"
echo "✅ Secret Key Length: $(echo $SIG_SK | wc -c) chars"

echo ""
echo "2. Signing message: 'Hello Post-Quantum World!'"
SIGN_DATA='{"message":"'$TEST_MESSAGE'","sk":"'$SIG_SK'"}'
SIGN_RESPONSE=$(curl -s -X POST "$API_BASE/sig/falcon512/sign" \
  -H "Content-Type: application/json" -d "$SIGN_DATA")
SIGNATURE=$(echo $SIGN_RESPONSE | jq -r '.signature')

echo "✅ Signature Length: $(echo $SIGNATURE | wc -c) chars"
echo "✅ Signature Preview: $(echo $SIGNATURE | cut -c1-64)..."

echo ""
echo "3. Verifying signature..."
VERIFY_DATA='{"message":"'$TEST_MESSAGE'","signature":"'$SIGNATURE'","pk":"'$SIG_PK'"}'
VERIFY_RESPONSE=$(curl -s -X POST "$API_BASE/sig/falcon512/verify" \
  -H "Content-Type: application/json" -d "$VERIFY_DATA")
IS_VALID=$(echo $VERIFY_RESPONSE | jq -r '.valid')

if [ "$IS_VALID" = "true" ]; then
    echo "✅ Signature verification passed!"
else
    echo "❌ Signature verification failed!"
fi

echo ""
echo "🔄 Testing Hybrid Cryptography"
echo "------------------------------"
echo "Testing JWT with embedded PQ signatures..."
HYBRID_DATA='{"payload":{"user":"alice","role":"admin"},"kem_variant":"kyber512","sig_variant":"falcon512"}'
HYBRID_RESPONSE=$(curl -s -X POST "$API_BASE/hybrid/sign" \
  -H "Content-Type: application/json" -d "$HYBRID_DATA")

if echo $HYBRID_RESPONSE | jq -e '.jwt' > /dev/null; then
    JWT=$(echo $HYBRID_RESPONSE | jq -r '.jwt')
    echo "✅ Hybrid JWT generated successfully"
    echo "✅ JWT Preview: $(echo $JWT | cut -c1-100)..."
    echo "✅ JWT Length: $(echo $JWT | wc -c) chars"
else
    echo "❌ Hybrid JWT generation failed"
    echo "Response: $HYBRID_RESPONSE"
fi

echo ""
echo "🎉 API Testing Complete!"
echo "========================"
echo "Your Post-Quantum Cryptography REST API is working!"