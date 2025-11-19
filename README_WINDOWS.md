# Quick Start for Windows AMD64

## Prerequisites Checklist

- [ ] Visual Studio 2019 or 2022 (with C++ tools)
- [ ] CMake (usually included with VS)
- [ ] Git
- [ ] libcurl (via vcpkg recommended)
- [ ] Hardware TPM 2.0 (most modern PCs have this)

## Quick Build

1. Open **Developer Command Prompt for VS** (or PowerShell with VS environment)

2. Navigate to project:
   ```cmd
   cd path\to\TpmWrapperFull
   ```

3. Run build script:
   ```cmd
   build.bat
   ```

4. Run the client:
   ```cmd
   build\bin\Release\tpm_client.exe http://your-server:8001
   ```

## Using vcpkg (Recommended)

If you're using vcpkg for dependencies:

```cmd
REM Install dependencies
vcpkg install curl:x64-windows
vcpkg install wolfssl:x64-windows

REM Build with vcpkg toolchain
cd TpmWrapperFull
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release ^
         -G "Visual Studio 17 2022" -A x64 ^
         -DCMAKE_TOOLCHAIN_FILE=C:\path\to\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build . --config Release
```

## Troubleshooting

**"CMake configuration failed"**
- Make sure Visual Studio is installed with C++ tools
- Try using Developer Command Prompt for VS

**"libcurl not found"**
- Install via vcpkg: `vcpkg install curl:x64-windows`
- Or configure CMake with `-DCURL_INCLUDE_DIR` and `-DCURL_LIBRARY`

**"TPM not available"**
- Check TPM in Windows: `tpm.msc` or `Get-Tpm` in PowerShell
- Make sure TPM is enabled in BIOS/UEFI

For detailed instructions, see `WINDOWS_BUILD.md`.

