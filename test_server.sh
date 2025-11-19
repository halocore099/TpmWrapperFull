#!/bin/bash

# Test script to debug server registration
# This automates the process of getting TPM data and calling the server

SERVER_URL="http://170.205.26.102:8001"

echo "============================================================"
echo "Automated Server Debugging Test"
echo "============================================================"
echo ""

# Check if swtpm is running
if [ ! -S /tmp/swtpm-sock ]; then
    echo "⚠️  swtpm not running. Starting it..."
    ./scripts/start_swtpm.sh > /dev/null 2>&1
    sleep 3
fi

# Step 1: Get attestation data
echo "Step 1: Getting attestation data from TPM..."
ATTEST_OUTPUT=$(./build/bin/test_attestation 2>&1)

# Extract the actual base64 values (they're printed on separate lines)
# Look for lines that contain base64-like strings (long alphanumeric strings)
EK_PUB=$(echo "$ATTEST_OUTPUT" | grep -E "^[A-Za-z0-9+/=]{100,}" | head -1)
AIK_NAME=$(echo "$ATTEST_OUTPUT" | grep -E "^[A-Za-z0-9+/=]{20,}" | tail -1)

# Alternative: extract from the "AIK name (base64):" line
if [ -z "$AIK_NAME" ]; then
    AIK_NAME=$(echo "$ATTEST_OUTPUT" | grep "AIK name (base64):" | sed 's/.*AIK name (base64): //')
fi

if [ -z "$EK_PUB" ] || [ -z "$AIK_NAME" ]; then
    echo "❌ Failed to get attestation data"
    echo "$ATTEST_OUTPUT"
    exit 1
fi

echo "✓ EK Public Key: ${EK_PUB:0:50}..."
echo "✓ AIK Name: ${AIK_NAME:0:50}..."
echo ""

# Step 2: Generate UUID
UUID=$(uuidgen 2>/dev/null || python3 -c "import uuid; print(uuid.uuid4())")
echo "Step 2: Generated UUID: $UUID"
echo ""

# Step 3: Build JSON payload
echo "Step 3: Building registration JSON..."
JSON_PAYLOAD=$(cat <<EOF
{
  "uuid": "$UUID",
  "ek_pub": "$EK_PUB",
  "ek_cert": "",
  "aik_name": "$AIK_NAME"
}
EOF
)

echo "JSON Payload:"
echo "$JSON_PAYLOAD" | python3 -m json.tool 2>/dev/null || echo "$JSON_PAYLOAD"
echo ""

# Step 4: Make registration request
echo "Step 4: Sending registration request to $SERVER_URL/register..."
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$JSON_PAYLOAD" \
    "$SERVER_URL/register" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE:/d')

echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body:"
echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Registration successful!"
    
    # Extract challenge data
    CHALLENGE_ID=$(echo "$BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('challenge_id', ''))" 2>/dev/null)
    if [ -n "$CHALLENGE_ID" ]; then
        echo "Challenge ID: $CHALLENGE_ID"
        echo ""
        echo "Next step: Activate credential and complete challenge"
    fi
else
    echo "❌ Registration failed"
    echo ""
    echo "Debugging info:"
    echo "- EK_PUB length: ${#EK_PUB}"
    echo "- AIK_NAME length: ${#AIK_NAME}"
    echo "- EK_PUB first 100 chars: ${EK_PUB:0:100}"
    echo "- AIK_NAME first 100 chars: ${AIK_NAME:0:100}"
fi

