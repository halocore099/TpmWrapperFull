#!/bin/bash

# Test script for TPM client
# Starts swtpm and runs the client

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
CLIENT_BIN="$BUILD_DIR/bin/tpm_client"

# Default server URL (can be overridden)
SERVER_URL="${1:-http://localhost:8000}"

echo "============================================================"
echo "TPM Client Test Script"
echo "============================================================"
echo ""

# Check if client is built
if [ ! -f "$CLIENT_BIN" ]; then
    echo "Error: Client not found at $CLIENT_BIN"
    echo "Please build the project first:"
    echo "  cd $PROJECT_ROOT"
    echo "  ./build.sh"
    exit 1
fi

# Check if swtpm is running
if [ ! -e "/tmp/swtpm-sock" ]; then
    echo "swtpm socket not found. Starting swtpm..."
    "$SCRIPT_DIR/start_swtpm.sh"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to start swtpm"
        exit 1
    fi
    sleep 2  # Give swtpm time to start
else
    echo "swtpm socket found, assuming swtpm is running"
fi

echo ""
echo "Running TPM client with server: $SERVER_URL"
echo ""

# Run the client
"$CLIENT_BIN" "$SERVER_URL"

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "Test completed successfully!"
else
    echo "Test failed with exit code: $EXIT_CODE"
fi

exit $EXIT_CODE

