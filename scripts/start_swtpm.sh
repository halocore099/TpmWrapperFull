#!/bin/bash

# Script to start swtpm simulator for development/testing

SWTPM_SOCKET="/tmp/swtpm-sock"
SWTPM_PORT=2321

echo "Starting swtpm simulator..."
echo "Socket: $SWTPM_SOCKET"
echo "Port: $SWTPM_PORT"
echo ""

# Check if swtpm is installed
if ! command -v swtpm &> /dev/null; then
    echo "Error: swtpm is not installed"
    echo "Install with:"
    echo "  macOS: brew install swtpm"
    echo "  Linux: sudo apt-get install swtpm swtpm-tools"
    exit 1
fi

# Check if socket already exists
if [ -e "$SWTPM_SOCKET" ]; then
    echo "Warning: Socket $SWTPM_SOCKET already exists"
    echo "If swtpm is already running, you can use it."
    echo "Otherwise, remove the socket and try again."
    exit 1
fi

# Create tpmstate directory if it doesn't exist
mkdir -p /tmp/swtpm-state

# Start swtpm in socket mode
# Use --flags not-need-init to skip platform interface initialization
echo "Starting swtpm..."
swtpm socket --tpm2 --port $SWTPM_PORT --ctrl type=unixio,path=$SWTPM_SOCKET --tpmstate dir=/tmp/swtpm-state --flags not-need-init --daemon

if [ $? -eq 0 ]; then
    echo "swtpm started successfully!"
    echo "Socket: $SWTPM_SOCKET"
    echo "Port: $SWTPM_PORT"
    echo ""
    echo "To stop swtpm, run:"
    echo "  pkill swtpm"
    echo "  rm -rf /tmp/swtpm-state"
else
    echo "Error: Failed to start swtpm"
    exit 1
fi

