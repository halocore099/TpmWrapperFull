#!/bin/bash

# Build script for Linux/macOS
# Auto-detects platform and architecture

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "TPM Client Build Script"
echo "============================================================"
echo ""

# Detect platform
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macOS"
else
    echo "Error: Unsupported platform: $OSTYPE"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
    ARCH_NAME="x86_64"
elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    ARCH_NAME="arm64"
else
    echo "Warning: Unknown architecture: $ARCH, assuming x86_64"
    ARCH_NAME="x86_64"
fi

echo "Platform: $PLATFORM"
echo "Architecture: $ARCH_NAME"
echo ""

# Check for required tools
echo "Checking for required tools..."

if ! command -v cmake &> /dev/null; then
    echo "Error: CMake is not installed"
    echo "Install with:"
    echo "  macOS: brew install cmake"
    echo "  Linux: sudo apt-get install cmake"
    exit 1
fi

if ! command -v make &> /dev/null && ! command -v ninja &> /dev/null; then
    echo "Error: No build system found (make or ninja)"
    exit 1
fi

# Check for libcurl
if ! pkg-config --exists libcurl; then
    echo "Warning: libcurl not found via pkg-config"
    echo "Trying to find it manually..."
    if [[ "$PLATFORM" == "macOS" ]]; then
        if [ -d "/usr/local/include/curl" ] || [ -d "/opt/homebrew/include/curl" ]; then
            echo "Found libcurl headers"
        else
            echo "Error: libcurl development headers not found"
            echo "Install with: brew install curl"
            exit 1
        fi
    else
        echo "Error: libcurl development package not found"
        echo "Install with: sudo apt-get install libcurl4-openssl-dev"
        exit 1
    fi
else
    echo "Found libcurl"
fi

# Check for wolfSSL (required by wolfTPM)
if ! pkg-config --exists wolfssl 2>/dev/null; then
    echo "Warning: wolfSSL not found via pkg-config"
    if [[ "$PLATFORM" == "macOS" ]]; then
        if [ -d "/opt/homebrew/opt/wolfssl/include" ] || [ -d "/usr/local/opt/wolfssl/include" ]; then
            echo "Found wolfSSL headers"
            # Set environment variables for CMake to find wolfSSL
            export CMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}:/opt/homebrew/opt/wolfssl:/usr/local/opt/wolfssl"
        else
            echo "Error: wolfSSL not found"
            echo "Install with: brew install wolfssl"
            exit 1
        fi
    fi
else
    echo "Found wolfSSL"
fi

echo ""

# Download dependencies if needed
echo "Checking dependencies..."

# Download wolfTPM
if [ ! -d "libs/wolfTPM" ]; then
    echo "Downloading wolfTPM..."
    mkdir -p libs
    cd libs
    git clone --depth 1 https://github.com/wolfSSL/wolfTPM.git || {
        echo "Error: Failed to clone wolfTPM"
        exit 1
    }
    cd ..
else
    echo "wolfTPM already present"
fi

# Download cJSON
if [ ! -d "libs/cJSON" ]; then
    echo "Downloading cJSON..."
    mkdir -p libs
    cd libs
    git clone --depth 1 https://github.com/DaveGamble/cJSON.git || {
        echo "Error: Failed to clone cJSON"
        exit 1
    }
    cd ..
else
    echo "cJSON already present"
fi

echo ""

# Create build directory
echo "Creating build directory..."
mkdir -p build
cd build

# Configure CMake
echo "Configuring CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
echo ""
echo "Building..."
if command -v ninja &> /dev/null; then
    cmake --build . --config Release
else
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
fi

echo ""
echo "============================================================"
echo "Build complete!"
echo "============================================================"
echo ""
echo "Executable: build/bin/tpm_client"
echo ""
echo "To run:"
echo "  ./build/bin/tpm_client <server_url> [uuid]"
echo ""

