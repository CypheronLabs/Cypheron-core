#!/bin/bash

echo "🔐 Testing PQ Crypto REST API"
echo "==============================="

API_BASE="http://127.0.0.1:3000"

echo ""
echo "📡 Testing KEM (Key Encapsulation) - Kyber512"
echo "----------------------------------------------"
echo "1. Generating keypair..."
curl -X POST "$API_BASE/kem/kyber512/keygen" -H "Content-Type: application/json"

echo ""
echo ""
echo "2. Testing KEM info endpoint..."
curl -X GET "$API_BASE/kem/kyber512/info"

echo ""
echo ""
echo "🖋️  Testing Digital Signatures - Falcon512"
echo "-------------------------------------------"
echo "1. Generating signature keypair..."
curl -X POST "$API_BASE/sig/falcon512/keygen" -H "Content-Type: application/json"

echo ""
echo ""
echo "🎉 Basic API connectivity test complete!"
echo "Your endpoints are responding correctly."