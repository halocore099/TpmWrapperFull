# Visual Studio Build Tools Setup Checklist

Complete list of everything you need to build and test the TPM Client using Visual Studio Build Tools.

## ✅ Required Components

### 1. Visual Studio Build Tools 2022 (or 2019)

**Download:** https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022

**Required Workloads:**
- ✅ **C++ build tools**
  - MSVC v143 - VS 2022 C++ x64/x86 build tools (or v142 for VS 2019)
  - Windows 10/11 SDK (latest version)
  - CMake tools for Windows (optional but recommended)

**Required Individual Components:**
- ✅ **MSVC v143 compiler toolset** (or v142 for VS 2019)
- ✅ **Windows 10/11 SDK** (latest version, e.g., 10.0.22621.0)
- ✅ **CMake tools for Windows** (or install CMake separately)

### 2. CMake (3.15 or later)

**Option A:** Included with VS Build Tools (if you selected "CMake tools for Windows")

**Option B:** Install separately
- Download: https://cmake.org/download/
- **Important:** Select "Add CMake to system PATH" during installation
- Verify: `cmake --version`

### 3. Git ✅ (Already installed - version 2.51.2)

Used for downloading dependencies (wolfTPM, cJSON)

### 4. Windows TBS (TPM Base Services)
   - **Built into Windows** - No installation needed
   - Used by wolfTPM's WINAPI interface for TPM access
   - Works on both Windows 10 and 11
   - Requires TPM 2.0 hardware

### 5. libcurl (Required for HTTP communication)

**Option 1 (Recommended): vcpkg**
```powershell
# Clone vcpkg
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg

# Bootstrap vcpkg
.\bootstrap-vcpkg.bat

# Install curl for x64 Windows
.\vcpkg install curl:x64-windows

# Note the path: C:\vcpkg\scripts\buildsystems\vcpkg.cmake
```

**Option 2: Pre-built binaries**
- Download: https://curl.se/windows/
- Extract to a folder (e.g., `C:\curl`)
- You'll need to configure CMake with paths to include/lib directories

### 5. TPM 2.0 Hardware

- Most modern Windows PCs have TPM 2.0
- Check status: Run PowerShell as Administrator → `Get-Tpm`
- Or use: `tpm.msc`

## 📋 Installation Checklist

### Step 1: Install Visual Studio Build Tools

1. Download Visual Studio Build Tools 2022
2. Run installer
3. Select **"C++ build tools"** workload
4. In **Individual components**, ensure:
   - ✅ MSVC v143 - VS 2022 C++ x64/x86 build tools
   - ✅ Windows 10/11 SDK (latest)
   - ✅ CMake tools for Windows (recommended)
5. Click **Install**

### Step 2: Verify CMake

Open **Developer Command Prompt for VS** (or PowerShell) and run:

```cmd
cmake --version
```

If not found:
- Install CMake separately from https://cmake.org/download/
- Make sure to add to PATH during installation

### Step 3: Install libcurl via vcpkg (Recommended)

```cmd
# Clone vcpkg
git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
cd C:\vcpkg

# Bootstrap
.\bootstrap-vcpkg.bat

# Install curl
.\vcpkg install curl:x64-windows
```

**Note the vcpkg path:** `C:\vcpkg\scripts\buildsystems\vcpkg.cmake`

### Step 4: Verify TPM

Run PowerShell as Administrator:

```powershell
Get-Tpm
```

Should show TPM is ready and enabled.

## 🚀 Quick Start After Installation

### 1. Open Developer Command Prompt

Press `Win + S`, search for **"Developer Command Prompt for VS"**

Or open PowerShell and run:
```powershell
# For VS 2022 Build Tools
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1"
```

### 2. Navigate to Project

```cmd
cd C:\Users\Navitank\Documents\bs\TpmWrapperFull
```

### 3. Build

**If using vcpkg:**
```cmd
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build . --config Release
```

**If NOT using vcpkg (and libcurl is in system):**
```cmd
build.bat
```

### 4. Run the Client

```cmd
cd ..
cd build\bin\Release
tpm_client.exe http://your-server:8001
```

## 📝 Complete Component List Summary

| Component | Status | Notes |
|-----------|--------|-------|
| Visual Studio Build Tools 2022 | ⚠️ Need to install | C++ build tools workload |
| MSVC Compiler (v143) | ⚠️ Included with Build Tools | Part of C++ build tools |
| Windows SDK | ⚠️ Included with Build Tools | Latest version |
| CMake 3.15+ | ⚠️ Need to verify | Included or install separately |
| Git | ✅ Installed | Version 2.51.2 |
| libcurl | ⚠️ Need to install | Via vcpkg (recommended) or pre-built |
| TPM 2.0 Hardware | ⚠️ Need to verify | Check with `Get-Tpm` |

## 🔍 Verification Commands

After installation, verify everything in Developer Command Prompt:

```cmd
# Check Visual Studio compiler
cl

# Check CMake
cmake --version

# Check Git
git --version

# Check vcpkg (if installed)
C:\vcpkg\vcpkg list

# Check TPM (PowerShell as Admin)
Get-Tpm
```

## ⚠️ Common Issues

### "cl is not recognized"
- Make sure you're using **Developer Command Prompt for VS**
- Or run `Launch-VsDevShell.ps1` in PowerShell

### "CMake not found"
- Install CMake separately and add to PATH
- Or reinstall VS Build Tools with "CMake tools for Windows"

### "libcurl not found" during CMake
- Make sure vcpkg is installed and curl is installed: `vcpkg install curl:x64-windows`
- Use `-DCMAKE_TOOLCHAIN_FILE` when running cmake

### "TPM not available"
- Check TPM is enabled in BIOS/UEFI
- Run `Get-Tpm` as Administrator
- Verify TPM 2.0 (not 1.2)

## 📚 Next Steps

1. Install Visual Studio Build Tools with C++ workload
2. Install/verify CMake
3. Install libcurl via vcpkg
4. Verify TPM hardware
5. Build: `build.bat` or manual CMake commands
6. Run: `build\bin\Release\tpm_client.exe http://your-server:8001`

See `WINDOWS_TEST_BUILD_GUIDE.md` for detailed testing instructions.


