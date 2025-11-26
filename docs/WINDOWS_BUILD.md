# Windows Build Instructions

Complete guide for building and running the TPM Client on Windows (x86_64 and ARM64).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installing Dependencies](#installing-dependencies)
3. [Downloading Bundled Libraries](#downloading-bundled-libraries)
4. [Building](#building)
5. [Running](#running)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Software

#### 1. Visual Studio 2019 or 2022

**Download:** https://visualstudio.microsoft.com/

**Installation Options:**
- **Full Visual Studio IDE**: Install with "Desktop development with C++" workload
- **Visual Studio Build Tools** (minimal): Install "C++ build tools" workload

**Required Components:**
- ✅ **MSVC compiler** (v142 for VS 2019, v143 for VS 2022)
- ✅ **Windows 10/11 SDK** (latest version)
- ✅ **CMake tools for Windows** (optional but recommended)

**Verification:**
```cmd
# Open Developer Command Prompt for VS
# Press Win + S, search for "Developer Command Prompt for VS"

# Check compiler
cl

# Check CMake
cmake --version
```

#### 2. CMake (3.15 or later)

**Option A:** Included with Visual Studio (if "CMake tools for Windows" was selected)

**Option B:** Install separately
- Download: https://cmake.org/download/
- **Important:** Select "Add CMake to system PATH" during installation
- Verify: `cmake --version`

#### 3. Git

Required for downloading dependencies (wolfTPM, cJSON, vcpkg).

- Download: https://git-scm.com/download/win
- Verify: `git --version`

#### 4. Windows TBS (TPM Base Services)

- **Built into Windows** - No installation needed
- Used by wolfTPM's WINAPI interface for TPM access
- Works on both Windows 10 and 11
- Requires TPM 2.0 hardware

**Verify TPM:**
```powershell
# Run PowerShell as Administrator
Get-Tpm
```

Or use: `tpm.msc`

### Hardware Requirements

- **TPM 2.0** chip (hardware TPM)
  - Most modern Windows PCs have TPM 2.0
  - Check in Windows: `tpm.msc` or `Get-Tpm` in PowerShell
  - The client uses Windows TBS (TPM Base Services) API directly
  - Works with Windows 10 and 11

## Installing Dependencies

### Step 1: Install vcpkg (C++ Package Manager)

vcpkg is used to install libcurl and wolfSSL.

```powershell
# Clone vcpkg to a location of your choice (e.g., C:\vcpkg)
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg

# Bootstrap vcpkg (this builds vcpkg itself)
.\bootstrap-vcpkg.bat

# Integrate vcpkg with Visual Studio (optional but recommended)
.\vcpkg integrate install
```

**Note the vcpkg path:** `C:\vcpkg\scripts\buildsystems\vcpkg.cmake`

### Step 2: Install libcurl via vcpkg

libcurl is required for HTTP communication with the backend server.

```powershell
cd C:\vcpkg

# For x64 Windows (most common)
.\vcpkg install curl:x64-windows

# For ARM64 Windows
.\vcpkg install curl:arm64-windows
```

**Verification:**
```powershell
.\vcpkg list
# Should show: curl:x64-windows
```

### Step 3: Install wolfSSL via vcpkg

wolfSSL is required by wolfTPM for cryptographic operations.

```powershell
cd C:\vcpkg

# For x64 Windows
.\vcpkg install wolfssl:x64-windows

# For ARM64 Windows
.\vcpkg install wolfssl:arm64-windows
```

**Verification:**
```powershell
.\vcpkg list
# Should show: curl:x64-windows and wolfssl:x64-windows
```

**Alternative:** If you prefer not to use vcpkg for wolfSSL, you can:
- Download from: https://www.wolfssl.com/download/
- Build from source: https://github.com/wolfSSL/wolfssl
- Configure CMake with `-DWOLFSSL_ROOT` pointing to your installation

## Downloading Bundled Libraries

**Important:** The `libs/` folder contents are **NOT** in the git repository (they're in `.gitignore`). You must download them manually or let the build script do it.

### Option 1: Automatic Download (Recommended)

The `build.bat` script will automatically download these if they don't exist:

```cmd
build.bat
```

### Option 2: Manual Download

If you prefer to download manually:

#### Download wolfTPM

```cmd
# Navigate to project root
cd path\to\TpmWrapperFull

# Create libs directory if it doesn't exist
if not exist libs mkdir libs
cd libs

# Clone wolfTPM (shallow clone for faster download)
git clone --depth 1 https://github.com/wolfSSL/wolfTPM.git

cd ..
```

**Verification:**
```cmd
dir libs\wolfTPM
# Should show CMakeLists.txt and other files
```

#### Download cJSON

```cmd
# Navigate to project root
cd path\to\TpmWrapperFull

# Create libs directory if it doesn't exist
if not exist libs mkdir libs
cd libs

# Clone cJSON (shallow clone for faster download)
git clone --depth 1 https://github.com/DaveGamble/cJSON.git

cd ..
```

**Verification:**
```cmd
dir libs\cJSON
# Should show CMakeLists.txt and other files
```

## Building

### Quick Build (Recommended)

1. **Open Developer Command Prompt for VS**
   - Press `Win + S`, search for **"Developer Command Prompt for VS"**
   - Or open PowerShell and run:
     ```powershell
     # For VS 2022
     & "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1"
     
     # For VS 2019
     & "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\Launch-VsDevShell.ps1"
     
     # For VS Build Tools 2022
     & "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1"
     ```

2. **Navigate to project directory:**
   ```cmd
   cd path\to\TpmWrapperFull
   ```

3. **Optional: Set VCPKG_ROOT** (if vcpkg is not in default location):
   ```cmd
   set VCPKG_ROOT=C:\vcpkg
   ```
   The build script will auto-detect vcpkg in:
   - `%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake` (if VCPKG_ROOT is set)
   - `C:\vcpkg\scripts\buildsystems\vcpkg.cmake`
   - `%USERPROFILE%\vcpkg\scripts\buildsystems\vcpkg.cmake`
   - `%LOCALAPPDATA%\vcpkg\scripts\buildsystems\vcpkg.cmake`

4. **Run the build script:**
   ```cmd
   build.bat
   ```

The script will:
- Auto-detect your architecture (AMD64 or ARM64)
- Auto-detect vcpkg toolchain (if installed)
- Download dependencies (wolfTPM, cJSON) if needed
- Automatically patch cJSON to fix `/Za` conflict
- Configure CMake with vcpkg toolchain (if found)
- Build the project

### Manual Build

If the build script doesn't work, you can build manually:

#### Step 1: Set vcpkg toolchain

```cmd
set CMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
```

(Replace `C:\vcpkg` with your actual vcpkg path)

#### Step 2: Configure CMake

```cmd
mkdir build
cd build

# For Visual Studio 2022
cmake .. -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 17 2022" -A x64

# For Visual Studio 2019
cmake .. -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 16 2019" -A x64

# Or let CMake auto-detect
cmake .. -DCMAKE_BUILD_TYPE=Release
```

#### Step 3: Build

```cmd
cmake --build . --config Release
```

### Using vcpkg with Manual Build

If you're using vcpkg for dependencies:

```cmd
set CMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake

mkdir build
cd build

cmake .. -DCMAKE_BUILD_TYPE=Release ^
         -G "Visual Studio 17 2022" -A x64 ^
         -DCMAKE_TOOLCHAIN_FILE=%CMAKE_TOOLCHAIN_FILE%

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

### With EK Format Option

```cmd
# Use Windows EK format (default)
build\bin\Release\tpm_client.exe http://server:8001 --ek-format=windows

# Use Persistent EK format
build\bin\Release\tpm_client.exe http://server:8001 --ek-format=persistent
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
4. Verify vcpkg toolchain is set correctly:
   ```cmd
   echo %CMAKE_TOOLCHAIN_FILE%
   # Should show: C:\vcpkg\scripts\buildsystems\vcpkg.cmake
   ```

### Error: "libcurl not found"

**Solutions:**
1. Install via vcpkg (recommended):
   ```cmd
   cd C:\vcpkg
   .\vcpkg install curl:x64-windows
   ```
2. Make sure vcpkg toolchain is set when running CMake:
   ```cmd
   set CMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
   ```
3. Or download pre-built binaries and configure CMake variables:
   ```cmd
   cmake .. -DCURL_INCLUDE_DIR=C:\path\to\curl\include ^
            -DCURL_LIBRARY=C:\path\to\curl\lib\libcurl.lib
   ```

### Error: "wolfSSL not found" or "wolfTPM build fails"

**Solutions:**
1. Install wolfSSL via vcpkg:
   ```cmd
   cd C:\vcpkg
   .\vcpkg install wolfssl:x64-windows
   ```
2. Make sure vcpkg toolchain is set when running CMake
3. Verify wolfSSL is installed:
   ```cmd
   .\vcpkg list
   # Should show: wolfssl:x64-windows
   ```
4. If using custom wolfSSL installation, set `WOLFSSL_ROOT`:
   ```cmd
   cmake .. -DWOLFSSL_ROOT=C:\path\to\wolfssl
   ```

### Error: "wolfTPM not found"

**Solutions:**
1. The build script should auto-download it
2. If it fails, manually clone:
   ```cmd
   if not exist libs mkdir libs
   cd libs
   git clone --depth 1 https://github.com/wolfSSL/wolfTPM.git
   cd ..
   ```
3. Verify it exists:
   ```cmd
   dir libs\wolfTPM
   # Should show CMakeLists.txt
   ```

### Error: "cJSON not found"

**Solutions:**
1. The build script should auto-download it
2. If it fails, manually clone:
   ```cmd
   if not exist libs mkdir libs
   cd libs
   git clone --depth 1 https://github.com/DaveGamble/cJSON.git
   cd ..
   ```
3. Verify it exists:
   ```cmd
   dir libs\cJSON
   # Should show CMakeLists.txt
   ```

### Error: "D8016: '/Za' and '/std:c11' command-line options are incompatible"

This error occurs when cJSON's CMakeLists.txt sets the `/Za` (ANSI mode) flag which conflicts with C11 standard.

**Solutions:**
1. **Automatic fix (recommended):** The `build.bat` script automatically patches cJSON's CMakeLists.txt to remove `/Za`. If you see this error:
   ```cmd
   # Clean and rebuild
   rmdir /s /q build
   rmdir /s /q libs\cJSON
   build.bat
   ```

2. **Manual fix:** If the automatic patch doesn't work, manually edit `libs\cJSON\CMakeLists.txt`:
   - Open `libs\cJSON\CMakeLists.txt` in a text editor
   - Search for `/Za` and remove all occurrences
   - Save the file
   - Rebuild: `cmake --build build --config Release`

3. **Alternative:** Disable cJSON tests (which often set `/Za`):
   ```cmd
   cd build
   cmake .. -DENABLE_CJSON_TEST=OFF -DENABLE_CJSON_UTILS=OFF
   cmake --build . --config Release
   ```

**Note:** The CMakeLists.txt has been updated to automatically fix this issue, but if you have an old cJSON clone, you may need to re-download it.

### Error: "Git not found"

**Solutions:**
1. Install Git from: https://git-scm.com/download/win
2. Make sure it's in your PATH
3. Restart your command prompt after installation
4. Verify: `git --version`

### Error: "vcpkg not found" or "CMAKE_TOOLCHAIN_FILE not set"

**Solutions:**
1. Install vcpkg (see [Installing Dependencies](#installing-dependencies))
2. Set the toolchain file:
   ```cmd
   set CMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
   ```
3. Or pass it directly to CMake:
   ```cmd
   cmake .. -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
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
3. Make sure you're running as Administrator (if required by TPM policy)
4. Restart computer if TPM shows "RestartPending: True"
5. Verify TPM 2.0 (not 1.2)

### Error: "cl is not recognized"

**Solutions:**
1. Make sure you're using **Developer Command Prompt for VS**
2. Or run `Launch-VsDevShell.ps1` in PowerShell:
   ```powershell
   & "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1"
   ```
3. Verify Visual Studio is installed with C++ tools

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
- Make sure vcpkg packages match your architecture:
  - `x64-windows` for AMD64
  - `arm64-windows` for ARM64

### vcpkg Integration

If you integrated vcpkg with Visual Studio (`vcpkg integrate install`), CMake should automatically find vcpkg packages. Otherwise, you must set `CMAKE_TOOLCHAIN_FILE` manually.

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

## Complete Installation Checklist

- [ ] Visual Studio 2019 or 2022 installed with C++ tools
- [ ] CMake 3.15+ installed and in PATH
- [ ] Git installed and in PATH
- [ ] vcpkg installed and bootstrapped
- [ ] libcurl installed via vcpkg (`vcpkg install curl:x64-windows`)
- [ ] wolfSSL installed via vcpkg (`vcpkg install wolfssl:x64-windows`)
- [ ] wolfTPM downloaded to `libs/wolfTPM/`
- [ ] cJSON downloaded to `libs/cJSON/`
- [ ] TPM 2.0 hardware verified (`Get-Tpm`)
- [ ] Build successful (`build.bat` or manual CMake)

## Next Steps

- See `../README.md` for general project information
- See `TPM2_ACTIVATECREDENTIAL_CODE.md` for TPM implementation details
- See `WINDOWS_TESTING.md` for testing instructions
- Check server logs if registration fails
