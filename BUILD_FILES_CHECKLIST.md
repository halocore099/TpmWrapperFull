# Build Files Checklist

This document verifies that all required build files are present and correctly configured.

## ✅ Required Build Files

### 1. **CMakeLists.txt** ✅
- **Location:** Root directory
- **Status:** Present and configured
- **Features:**
  - CMake minimum version: 3.15
  - C standard: C11
  - Platform detection: Windows, Linux, macOS
  - Architecture detection: x86_64, ARM64
  - Source files: All 8 source files included
  - Header files: All 7 header files included (fixed: added ek_cert_gen.h)
  - Dependencies: wolfTPM, cJSON, libcurl
  - cJSON fixes: /Za flag removal, CMake version update

### 2. **build.bat** ✅
- **Location:** Root directory
- **Status:** Present and configured
- **Features:**
  - Auto-detects architecture (x86_64, ARM64)
  - Auto-detects vcpkg toolchain (C:\vcpkg, VCPKG_ROOT, etc.)
  - Downloads wolfTPM if missing
  - Downloads cJSON if missing
  - Patches cJSON CMakeLists.txt:
    - Removes /Za flags (MSVC conflict)
    - Updates cmake_minimum_required to 3.5
  - Cleans build directory if needed
  - Configures CMake with vcpkg toolchain
  - Builds with Visual Studio 2022/2019 or default generator

### 3. **build.sh** ✅
- **Location:** Root directory
- **Status:** Present and configured
- **Features:**
  - Auto-detects platform (Linux, macOS)
  - Auto-detects architecture (x86_64, ARM64)
  - Downloads wolfTPM if missing
  - Downloads cJSON if missing
  - Configures and builds with CMake

## ✅ Source Files

### Source Files (8 files) ✅
1. `src/main.c` ✅
2. `src/tpm_wrapper.c` ✅
3. `src/platform_tpm.c` ✅
4. `src/http_client.c` ✅
5. `src/base64.c` ✅
6. `src/json_utils.c` ✅
7. `src/logger.c` ✅
8. `src/ek_cert_gen.c` ✅

### Header Files (7 files) ✅
1. `src/tpm_wrapper.h` ✅
2. `src/platform_tpm.h` ✅
3. `src/http_client.h` ✅
4. `src/base64.h` ✅
5. `src/json_utils.h` ✅
6. `src/logger.h` ✅
7. `src/ek_cert_gen.h` ✅ (now included in CMakeLists.txt)

## ✅ Dependencies

### Bundled Dependencies (Auto-downloaded)
1. **wolfTPM** ✅
   - Location: `libs/wolfTPM/`
   - Auto-downloaded by build scripts
   - Built via `add_subdirectory()` in CMakeLists.txt
   - Requires: wolfSSL (via vcpkg on Windows)

2. **cJSON** ✅
   - Location: `libs/cJSON/`
   - Auto-downloaded by build scripts
   - Built via `add_subdirectory()` in CMakeLists.txt
   - Auto-patched to fix:
     - `/Za` flag removal (MSVC conflict)
     - `cmake_minimum_required` update to 3.5

### External Dependencies (Manual Installation Required)
1. **libcurl** ✅
   - Windows: Install via vcpkg (`vcpkg install curl:x64-windows`)
   - Linux: Install via package manager (`apt-get install libcurl4-openssl-dev`)
   - macOS: Install via Homebrew (`brew install curl`)

2. **wolfSSL** ✅
   - Windows: Install via vcpkg (`vcpkg install wolfssl:x64-windows`)
   - Linux: Install via package manager or build from source
   - macOS: Install via Homebrew (`brew install wolfssl`)

3. **libuuid** (Linux only) ✅
   - Linux: Install via package manager (`apt-get install libuuid-dev`)

## ✅ Build Configuration

### CMake Configuration
- **Minimum CMake Version:** 3.15
- **C Standard:** C11
- **Build Type:** Release (default)
- **Output Directory:** `build/bin/`
- **Platform Support:**
  - Windows: TBS API (via wolfTPM WINAPI interface)
  - Linux: /dev/tpm0 or swtpm socket
  - macOS: swtpm socket

### Compiler Options
- **GCC/Clang:** `-Wall -Wextra -Wpedantic`, `-O2` (Release), `-g -O0` (Debug)
- **MSVC:** Standard MSVC options (no custom flags)

### Library Linking
- **Libraries Linked:**
  - `${CURL_LIBRARIES}` - libcurl
  - `${WOLFTPM_LIB}` - wolfTPM (wolftpm)
  - `${CJSON_LIB}` - cJSON (cjson)
  - `${PLATFORM_LIBS}` - Platform-specific (tbs on Windows, uuid on Linux, rpcrt4 on Windows)

## ✅ Build Script Features

### build.bat (Windows)
- ✅ Architecture auto-detection
- ✅ vcpkg auto-detection (C:\vcpkg, VCPKG_ROOT, etc.)
- ✅ Git check
- ✅ CMake check
- ✅ Dependency download (wolfTPM, cJSON)
- ✅ cJSON patching (/Za removal, CMake version)
- ✅ Build directory cleanup
- ✅ CMake configuration with vcpkg
- ✅ Visual Studio generator selection (2022 → 2019 → default)
- ✅ Build execution
- ✅ Executable location reporting

### build.sh (Linux/macOS)
- ✅ Platform auto-detection
- ✅ Architecture auto-detection
- ✅ Required tools check (CMake, Git, pkg-config)
- ✅ Dependency check (libcurl, wolfSSL)
- ✅ Dependency download (wolfTPM, cJSON)
- ✅ CMake configuration
- ✅ Build execution
- ✅ Executable location reporting

## ✅ Verification Commands

### Check Build Files
```bash
# Windows
dir build.bat
dir CMakeLists.txt

# Linux/macOS
ls -la build.sh
ls -la CMakeLists.txt
```

### Check Source Files
```bash
# All platforms
ls -la src/*.c
ls -la src/*.h
```

### Check Dependencies
```bash
# Windows
dir libs\wolfTPM\CMakeLists.txt
dir libs\cJSON\CMakeLists.txt

# Linux/macOS
ls -la libs/wolfTPM/CMakeLists.txt
ls -la libs/cJSON/CMakeLists.txt
```

### Verify Build Configuration
```bash
# Windows
cd build
cmake .. --graphviz=deps.dot

# Linux/macOS
cd build
cmake .. --graphviz=deps.dot
```

## ✅ Summary

All build files are present and correctly configured:
- ✅ CMakeLists.txt - Complete with all source/header files
- ✅ build.bat - Complete with vcpkg detection and cJSON patching
- ✅ build.sh - Complete for Linux/macOS
- ✅ All 8 source files included
- ✅ All 7 header files included
- ✅ Dependencies auto-downloaded (wolfTPM, cJSON)
- ✅ External dependencies documented (libcurl, wolfSSL)

**Status: All build files verified and ready for use!**

