# Windows Testing Guide

Complete guide for building and testing the TPM Client on Windows.

## Quick Start

### 1. Build the Project

```cmd
# Open Developer Command Prompt for Visual Studio
# Navigate to project directory
cd C:\Users\Navitank\Documents\bs\TpmWrapperFull

# Build everything (including tests)
build.bat
```

### 2. Run the Client

```cmd
cd build\bin\Release
tpm_client.exe http://your-server:8001
```

## Prerequisites

### Required Software

1. **Visual Studio 2019 or 2022**
   - Download: https://visualstudio.microsoft.com/
   - Install with "Desktop development with C++" workload
   - Includes: MSVC compiler, CMake, Windows SDK

2. **CMake** (3.15 or later)
   - Usually included with Visual Studio
   - Or download from: https://cmake.org/download/
   - Verify: `cmake --version`

3. **Git** - For downloading dependencies

4. **libcurl** - Required for HTTP communication
   - **Recommended: vcpkg**
     ```powershell
     git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
     cd C:\vcpkg
     .\bootstrap-vcpkg.bat
     .\vcpkg install curl:x64-windows
     ```

### Hardware Requirements

- **TPM 2.0** chip (hardware TPM)
- Check TPM status: `tpm.msc` or PowerShell: `Get-Tpm`
- Verify TPM is enabled in BIOS/UEFI

## Running the Client

The main client executable is `tpm_client.exe`:

```cmd
cd build\bin\Release
tpm_client.exe http://your-server:8001
```

**What it does:**
- TPM initialization
- EK retrieval (from Windows TPM Management Provider or TPM NVRAM)
- AIK creation in endorsement hierarchy
- Server registration
- Credential activation

## Troubleshooting

### Error: "TPM not available (TBS error: 0x8028400f)"

**Solutions:**
1. Check TPM is enabled: `Get-Tpm` in PowerShell
2. Verify TPM in Device Manager: `devmgmt.msc` → Security Devices
3. Check TPM Management: `tpm.msc`
4. Ensure TPM is not in "RestartPending" state
5. Restart computer if needed
6. Run as Administrator if required by TPM policy

### Error: "CMake not found"

**Solutions:**
1. Use Visual Studio Developer PowerShell (run `scripts\setup_vs_env.ps1`)
2. Or add CMake to PATH manually
3. Or use Visual Studio's built-in CMake support

### Error: "libcurl not found"

**Solutions:**
1. Install via vcpkg: `.\vcpkg install curl:x64-windows`
2. Configure CMake with vcpkg toolchain:
   ```cmd
   cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
   ```

## Expected Flow

When running `tpm_client.exe`:

1. Initialize TPM connection (via TBS)
2. Get/create EK (Endorsement Key)
3. Create AIK in endorsement hierarchy (under EK)
4. Register with the server
5. Activate credential
6. Complete the challenge

## Verification Checklist

After building and running the client, verify:

- [ ] EK is retrieved successfully
- [ ] AIK is created in endorsement hierarchy (not under SRK)
- [ ] Server registration completes successfully
- [ ] Credential activation completes successfully
- [ ] No TPM errors in the output

