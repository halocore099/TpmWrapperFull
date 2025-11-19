# TPM Client - Cross-Platform TPM Attestation Client

A cross-platform TPM 2.0 client built with wolfTPM that can register and attest to a backend server. Supports Linux (x86_64, ARM64) and Windows (x86_64, ARM64).

## Features

- **Cross-Platform Support**: Linux (x86_64, ARM64) and Windows (x86_64, ARM64)
- **TPM Operations**: Endorsement Key (EK) management, Attestation Identity Key (AIK) creation, Credential activation
- **Backend Integration**: Full integration with `/register` and `/completeChallenge` endpoints
- **Easy Setup**: One-click build scripts for each platform
- **Development Support**: Works with swtpm simulator for testing

## Requirements

### All Platforms
- CMake 3.15 or higher
- C compiler (GCC, Clang, or MSVC)
- libcurl development libraries
- Git (for downloading dependencies)

### Linux
- libcurl-dev or libcurl-devel
- libuuid-dev (for UUID generation)
- swtpm (optional, for simulator testing)
- Hardware TPM or swtpm for actual TPM operations

### Windows
- libcurl (via vcpkg or pre-built binaries)
- Visual Studio 2019 or later (for building)
- Hardware TPM (fTPM or discrete TPM)
- Git for Windows (for downloading dependencies)

## Quick Start

### Linux

```bash
# Clone the repository
git clone <repository-url>
cd TpmWrapperFull

# Install dependencies (if not already installed)
sudo apt-get install cmake build-essential libcurl4-openssl-dev libuuid-dev

# For development/testing with swtpm simulator:
sudo apt-get install swtpm swtpm-tools

# Run build script (auto-detects architecture: x86_64 or ARM64)
./build.sh

# The executable will be in build/bin/tpm_client
./build/bin/tpm_client <server_url> [uuid]
```

### Windows

```powershell
# Clone the repository
git clone <repository-url>
cd TpmWrapperFull

# Install dependencies:
# - CMake: https://cmake.org/download/
# - Visual Studio 2019 or later with C++ tools
# - libcurl: Install via vcpkg or download pre-built binaries

# Run build script (auto-detects architecture: x86_64 or ARM64)
.\build.bat

# The executable will be in build\bin\Release\tpm_client.exe
.\build\bin\Release\tpm_client.exe <server_url> [uuid]
```

## Building

The build scripts automatically:
1. Detect your platform and architecture
2. Check for required dependencies
3. Download wolfTPM and cJSON if needed
4. Build all components
5. Create a single executable

### Manual Build

If you prefer to build manually:

```bash
mkdir build
cd build
cmake ..
make  # or 'cmake --build .' on Windows
```

## Usage

### Basic Usage

```bash
./tpm_client <server_url> [uuid]
```

Example:
```bash
./tpm_client http://192.168.1.100:8000
```

### What It Does

1. Connects to TPM (hardware or swtpm simulator)
2. Gets attestation data (EK public key, EK certificate, AIK name)
3. Registers with the backend server
4. Receives a challenge from the server
5. Activates the credential using TPM
6. Completes the challenge with the server

## Development with swtpm (Linux/macOS)

For development and testing without a hardware TPM:

```bash
# Start swtpm simulator
./scripts/start_swtpm.sh

# In another terminal, run the client
./build/bin/tpm_client <server_url>

# Or use the test script which starts swtpm automatically
./scripts/test_client.sh <server_url>
```

### macOS

On macOS, you'll need to install swtpm via Homebrew:

```bash
brew install swtpm

# Then start swtpm
./scripts/start_swtpm.sh
```

## Project Structure

```
TpmWrapperFull/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── src/                    # Source code
│   ├── main.c             # Main entry point
│   ├── tpm_wrapper.c      # TPM operations
│   ├── platform_tpm.c     # Platform-specific TPM connection
│   ├── http_client.c      # HTTP communication
│   ├── base64.c           # Base64 encoding/decoding
│   └── json_utils.c       # JSON utilities
├── libs/                   # Dependencies
│   ├── wolfTPM/           # wolfTPM library (downloaded by build script)
│   └── cJSON/             # cJSON library (downloaded by build script)
├── scripts/                # Build and utility scripts
│   ├── build.sh           # Linux build script
│   ├── build.bat          # Windows build script
│   └── start_swtpm.sh     # Start swtpm simulator
└── build/                  # Build output
```

## Backend API

The client communicates with a backend server that provides:

- `POST /register` - Register with EK and AIK data
  - Request: `{uuid, ek_pub, ek_cert, aik_name}`
  - Response: `{challenge_id, credential_blob, encrypted_secret, hmac, enc}`

- `POST /completeChallenge` - Complete the attestation challenge
  - Request: `{challenge_id, decrypted_secret}`
  - Response: Success/failure status

## Troubleshooting

### Build Issues

**libcurl not found:**
- Linux: Install `libcurl-dev` or `libcurl-devel`
  ```bash
  sudo apt-get install libcurl4-openssl-dev  # Debian/Ubuntu
  sudo yum install libcurl-devel             # RHEL/CentOS
  ```
- Windows: Install via vcpkg:
  ```powershell
  vcpkg install curl
  ```

**UUID library not found (Linux):**
- Install `libuuid-dev`:
  ```bash
  sudo apt-get install libuuid-dev
  ```

**wolfTPM build fails:**
- Ensure CMake 3.15+ is installed
- Check that C compiler is available
- Verify Git is installed (needed to download dependencies)

**cJSON build fails:**
- The build script should download cJSON automatically
- If it fails, manually clone: `git clone https://github.com/DaveGamble/cJSON.git libs/cJSON`

### Runtime Issues

**TPM not found:**
- Linux: 
  - Check if hardware TPM exists: `ls -l /dev/tpm0`
  - For development, start swtpm: `./scripts/start_swtpm.sh`
  - Check TPM status: `tpm2_getcap properties-variable`
- Windows: 
  - Ensure TPM is enabled in BIOS/UEFI
  - Check TPM status: `tpm.msc` or PowerShell: `Get-Tpm`
  - Verify TBS service is running

**Connection to server fails:**
- Verify server URL is correct (include `http://` or `https://`)
- Check network connectivity: `ping <server_ip>`
- Ensure server is running and accessible
- Check firewall settings
- Verify server port is correct

**Registration fails:**
- Check server logs for error messages
- Verify server expects the correct JSON format
- Ensure TPM attestation data is valid

**Credential activation fails:**
- Verify challenge data from server is correct
- Check that EK and AIK are properly created
- Ensure TPM has proper authorization

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]

