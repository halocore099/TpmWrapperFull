# Windows Build Instructions

This guide will help you build and run the TPM Client on Windows AMD64.

## Prerequisites

### Required Software

1. **Visual Studio 2019 or 2022**
   - Install with "Desktop development with C++" workload
   - Includes MSVC compiler and CMake support
   - Download from: https://visualstudio.microsoft.com/

2. **CMake** (3.15 or later)
   - Usually included with Visual Studio
   - Or download from: https://cmake.org/download/
   - Make sure it's in your PATH

3. **Git**
   - Required for downloading dependencies (wolfTPM, cJSON)
   - Download from: https://git-scm.com/download/win

4. **libcurl**
   - **Option 1 (Recommended): vcpkg**
     ```cmd
     git clone https://github.com/Microsoft/vcpkg.git
     cd vcpkg
     .\bootstrap-vcpkg.bat
     .\vcpkg install curl:x64-windows
     ```
     Then configure CMake with:
     ```cmd
     cmake .. -DCMAKE_TOOLCHAIN_FILE=[path to vcpkg]/scripts/buildsystems/vcpkg.cmake
     ```

   - **Option 2: Pre-built binaries**
     - Download from: https://curl.se/windows/
     - Extract and add to PATH or configure CMake variables

### Hardware Requirements

- **TPM 2.0** chip (hardware TPM)
  - Most modern Windows PCs have TPM 2.0
  - Check in Windows: `tpm.msc` or `Get-Tpm` in PowerShell
  - The client uses Windows TBS (TPM Base Services) API directly
  - Works with Windows 10 and 11

## Building

### Quick Build

1. Open **Developer Command Prompt for VS** (or PowerShell with VS environment)

2. Navigate to the project directory:
   ```cmd
   cd path\to\TpmWrapperFull
   ```

3. Run the build script:
   ```cmd
   build.bat
   ```

The script will:
- Auto-detect your architecture (AMD64)
- Download dependencies (wolfTPM, cJSON) if needed
- Configure CMake
- Build the project

### Manual Build

If the build script doesn't work, you can build manually:

```cmd
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Using vcpkg

If you're using vcpkg for dependencies:

```cmd
cmake .. -DCMAKE_BUILD_TYPE=Release ^
         -G "Visual Studio 17 2022" -A x64 ^
         -DCMAKE_TOOLCHAIN_FILE=C:\path\to\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build . --config Release
```

## Output

The executable will be at:
```
build\bin\Release\tpm_client.exe
```

## Running

### Basic Usage

```cmd
build\bin\Release\tpm_client.exe http://server:8001
```

### With Custom UUID

```cmd
build\bin\Release\tpm_client.exe http://server:8001 550e8400-e29b-41d4-a716-446655440000
```

### Debug Mode

```cmd
set TPM_LOG_LEVEL=DEBUG
build\bin\Release\tpm_client.exe http://server:8001
```

## Troubleshooting

### Error: "CMake configuration failed"

**Solutions:**
1. Make sure Visual Studio is installed with C++ tools
2. Check that CMake is in your PATH: `cmake --version`
3. Try using Developer Command Prompt for VS

### Error: "libcurl not found"

**Solutions:**
1. Install via vcpkg (recommended):
   ```cmd
   vcpkg install curl:x64-windows
   ```
2. Or download pre-built binaries and configure CMake variables:
   ```cmd
   cmake .. -DCURL_INCLUDE_DIR=C:\path\to\curl\include ^
            -DCURL_LIBRARY=C:\path\to\curl\lib\libcurl.lib
   ```

### Error: "TPM not available"

**Solutions:**
1. Check if TPM is enabled in BIOS/UEFI
2. Verify TPM is accessible:
   ```cmd
   tpm.msc
   ```
   Or in PowerShell:
   ```powershell
   Get-Tpm
   ```
4. Make sure you're running as Administrator (if required by TPM policy)
5. Restart computer if TPM shows "RestartPending: True"

### Error: "wolfTPM not found"

**Solutions:**
1. The build script should auto-download it
2. If it fails, manually clone:
   ```cmd
   git clone --depth 1 https://github.com/wolfSSL/wolfTPM.git libs\wolfTPM
   ```

### Error: "Git not found"

**Solutions:**
1. Install Git from: https://git-scm.com/download/win
2. Make sure it's in your PATH
3. Restart your command prompt after installation

## Platform-Specific Notes

### Windows TPM Access

- The client uses **Windows TBS (TPM Base Services)** API directly
- wolfTPM's WINAPI interface communicates with TBS natively
- Works with hardware TPM 2.0 chips on Windows 10 and 11
- **Note:** Software TPM simulators (like swtpm) are not available on Windows
  - For development, use a machine with hardware TPM
  - Or use WSL2 with Linux build for swtpm testing

### Architecture

- The build script auto-detects AMD64 architecture
- For ARM64 Windows, the script will detect and build accordingly
- Visual Studio generator will be set to match your architecture

## Testing

After building, test the client:

```cmd
build\bin\Release\tpm_client.exe http://your-server:8001
```

The client will:
1. Initialize TPM connection (via Windows TBS)
2. Get/create EK (Endorsement Key)
3. Create AIK in endorsement hierarchy (under EK)
4. Register with the server
5. Activate credential
6. Complete the challenge

## Next Steps

- See `../README.md` for general project information
- See `BACKEND_ISSUE.md` for backend compatibility notes
- Check server logs if registration fails

