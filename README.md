# TPM Client - Cross-Platform TPM Attestation Client

A cross-platform TPM 2.0 client built with wolfTPM that can register and attest to a backend server. Supports Linux (x86_64, ARM64) and Windows (x86_64, ARM64).

## Features

- **Cross-Platform Support**: Linux (x86_64, ARM64) and Windows (x86_64, ARM64)
- **TPM Operations**: Endorsement Key (EK) management, Attestation Identity Key (AIK) creation, Credential activation
- **Backend Integration**: Full integration with `/register` and `/completeChallenge` endpoints
- **Easy Setup**: One-click build scripts for each platform
- **Development Support**: Works with swtpm simulator for testingwh

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
- Visual Studio 2019 or later (for building) with C++ tools
- vcpkg (for dependency management)
- Hardware TPM (fTPM or discrete TPM)
- Git for Windows (for downloading dependencies)
- CMake 3.15 or higher

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

**See [docs/WINDOWS_BUILD.md](docs/WINDOWS_BUILD.md) for complete Windows build instructions.**

Quick start:

```powershell
# 1. Install Visual Studio 2019 or 2022 with C++ tools
# 2. Install vcpkg and dependencies (see WINDOWS_BUILD.md)
# 3. Clone repository
git clone <repository-url>
cd TpmWrapperFull

# 4. Set vcpkg toolchain (replace C:\vcpkg with your path)
$env:CMAKE_TOOLCHAIN_FILE = "C:\vcpkg\scripts\buildsystems\vcpkg.cmake"

# 5. Build
.\build.bat

# 6. Run
.\build\bin\Release\tpm_client.exe <server_url> [uuid]
```

**Required dependencies:**
- Visual Studio 2019 or 2022 with C++ tools
- vcpkg (for libcurl and wolfSSL)
- Git (for downloading wolfTPM and cJSON)
- TPM 2.0 hardware

**Note:** The `libs/` folder (wolfTPM, cJSON) is not in the git repository. The build script will download them automatically, or see `docs/WINDOWS_BUILD.md` for manual download instructions.

## Building

The build scripts automatically:
1. Detect your platform and architecture
2. Check for required dependencies
3. Download wolfTPM and cJSON if needed
4. Build all components
5. Create a single executable

### Dependencies

#### Linux Dependencies
- **libcurl**: HTTP client library
  ```bash
  sudo apt-get install libcurl4-openssl-dev  # Debian/Ubuntu
  sudo yum install libcurl-devel             # RHEL/CentOS
  ```
- **libuuid**: UUID generation
  ```bash
  sudo apt-get install libuuid-dev
  ```
- **wolfTPM**: TPM 2.0 library (bundled, downloaded automatically)
- **cJSON**: JSON parsing (bundled, downloaded automatically)

#### Windows Dependencies (via vcpkg)

Required vcpkg packages:
- **curl**: HTTP client library
  ```powershell
  .\vcpkg install curl:x64-windows
  ```
- **wolfssl**: Required by wolfTPM for cryptographic operations
  ```powershell
  .\vcpkg install wolfssl:x64-windows
  ```

Optional but recommended:
- **vcpkg integration**: Integrate vcpkg with Visual Studio
  ```powershell
  .\vcpkg integrate install
  ```

**Note**: 
- wolfTPM and cJSON are bundled dependencies that are automatically downloaded and built by the build scripts. They are **not** in the git repository (see `.gitignore`).
- See `docs/WINDOWS_BUILD.md` for complete installation instructions.

### Manual Build

#### Linux
```bash
mkdir build
cd build
cmake ..
make
```

#### Windows
```powershell
# Set vcpkg toolchain (replace with your vcpkg path)
$env:CMAKE_TOOLCHAIN_FILE = "C:\vcpkg\scripts\buildsystems\vcpkg.cmake"

mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
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

## Documentation

Additional documentation is available in the `docs/` directory:
- **Windows Build**: `docs/WINDOWS_BUILD.md` - **Complete Windows build instructions** (vcpkg setup, wolfSSL installation, wolfTPM/cJSON download)
- **TPM2_ActivateCredential Code**: `docs/TPM2_ACTIVATECREDENTIAL_CODE.md` - Complete implementation code for TPM2_ActivateCredential with error handling
- **Windows Testing**: `docs/WINDOWS_TESTING.md` - Windows testing instructions
- **Backend Issues**: `docs/BACKEND_ISSUE.md` - Backend compatibility notes
- **API Verification**: `docs/API_VERIFICATION.md` - API endpoint verification

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
  # Make sure vcpkg is installed and bootstrapped
  cd C:\vcpkg
  .\vcpkg install curl:x64-windows
  
  # Then configure CMake with vcpkg toolchain:
  $env:CMAKE_TOOLCHAIN_FILE = "C:\vcpkg\scripts\buildsystems\vcpkg.cmake"
  # Or pass it to CMake:
  cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
  ```

**vcpkg not found (Windows):**
- See `docs/WINDOWS_BUILD.md` for complete vcpkg installation instructions
- Install vcpkg:
  ```powershell
  git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
  cd C:\vcpkg
  .\bootstrap-vcpkg.bat
  ```
- Ensure CMake can find vcpkg by setting `CMAKE_TOOLCHAIN_FILE`:
  ```powershell
  $env:CMAKE_TOOLCHAIN_FILE = "C:\vcpkg\scripts\buildsystems\vcpkg.cmake"
  ```

**CMake can't find vcpkg packages:**
- Verify vcpkg packages are installed:
  ```powershell
  .\vcpkg list
  ```
- Reinstall packages if needed:
  ```powershell
  .\vcpkg remove curl:x64-windows
  .\vcpkg install curl:x64-windows
  .\vcpkg install wolfssl:x64-windows
  ```
- Ensure architecture matches (x64-windows vs arm64-windows)

**wolfSSL not found:**
- Install via vcpkg:
  ```powershell
  .\vcpkg install wolfssl:x64-windows
  ```
- See `docs/WINDOWS_BUILD.md` for detailed instructions

**wolfTPM or cJSON not found:**
- These are downloaded automatically by `build.bat`
- If download fails, manually clone:
  ```cmd
  if not exist libs mkdir libs
  cd libs
  git clone --depth 1 https://github.com/wolfSSL/wolfTPM.git
  git clone --depth 1 https://github.com/DaveGamble/cJSON.git
  ```
- See `docs/WINDOWS_BUILD.md` for complete instructions

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
  - Uses Windows TBS (TPM Base Services) API for TPM access

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
