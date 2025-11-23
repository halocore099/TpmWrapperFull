@echo off
REM Build script for Windows
REM Auto-detects architecture

setlocal enabledelayedexpansion

echo ============================================================
echo TPM Client Build Script (Windows)
echo ============================================================
echo.

REM Detect architecture
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set ARCH_NAME=x86_64
) else if "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    set ARCH_NAME=arm64
) else (
    echo Warning: Unknown architecture: %PROCESSOR_ARCHITECTURE%, assuming x86_64
    set ARCH_NAME=x86_64
)

echo Platform: Windows
echo Architecture: %ARCH_NAME%
echo.

REM Check for CMake
where cmake >nul 2>&1
if errorlevel 1 (
    echo Error: CMake is not installed or not in PATH
    echo Install from: https://cmake.org/download/
    exit /b 1
)
echo Found CMake

REM Check for libcurl
echo Checking for libcurl...
where curl.exe >nul 2>&1
if errorlevel 1 (
    echo Warning: curl.exe not found in PATH
    echo This is OK if libcurl is installed via vcpkg or other package manager
)
echo.
echo Note: libcurl should be installed via one of:
echo   - vcpkg: vcpkg install curl:x64-windows
echo   - Pre-built binaries from curl.se
echo   - Visual Studio vcpkg integration
echo.

REM Check for Git
where git >nul 2>&1
if errorlevel 1 (
    echo Error: Git is not installed or not in PATH
    echo Install from: https://git-scm.com/download/win
    exit /b 1
)
echo Found Git

REM Download dependencies if needed
echo Checking dependencies...

if not exist "libs\wolfTPM" (
    echo Downloading wolfTPM...
    if not exist libs mkdir libs
    cd libs
    git clone --depth 1 https://github.com/wolfSSL/wolfTPM.git
    if errorlevel 1 (
        echo Error: Failed to clone wolfTPM
        echo Make sure you have internet connection and Git is working
        exit /b 1
    )
    cd ..
) else (
    echo wolfTPM already present
)

if not exist "libs\cJSON" (
    echo Downloading cJSON...
    if not exist libs mkdir libs
    cd libs
    git clone --depth 1 https://github.com/DaveGamble/cJSON.git
    if errorlevel 1 (
        echo Error: Failed to clone cJSON
        echo Make sure you have internet connection and Git is working
        exit /b 1
    )
    cd ..
) else (
    echo cJSON already present
)


echo.

REM Create build directory
echo Creating build directory...
if not exist build mkdir build
cd build

REM Configure CMake
echo Configuring CMake...
REM Try Visual Studio 2022 first, then 2019, then default
cmake .. -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo Visual Studio 2022 not found, trying Visual Studio 2019...
    cmake .. -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 16 2019" -A x64
    if errorlevel 1 (
        echo Visual Studio 2019 not found, trying default generator...
        cmake .. -DCMAKE_BUILD_TYPE=Release
        if errorlevel 1 (
            echo Error: CMake configuration failed
            echo.
            echo Please ensure:
            echo   1. CMake is installed and in PATH
            echo   2. Visual Studio 2019 or 2022 is installed (with C++ tools)
            echo   3. libcurl is available (via vcpkg or pre-built)
            echo   4. Git is installed (for downloading dependencies)
            exit /b 1
        )
    )
)

REM Build
echo.
echo Building...
cmake --build . --config Release
if errorlevel 1 (
    echo Error: Build failed
    exit /b 1
)

echo.
echo ============================================================
echo Build complete!
echo ============================================================
echo.

REM Check if executable exists
if exist "bin\Release\tpm_client.exe" (
    echo Executable: build\bin\Release\tpm_client.exe
    echo.
    echo To run:
    echo   build\bin\Release\tpm_client.exe ^<server_url^> [uuid]
    echo.
    echo Example:
    echo   build\bin\Release\tpm_client.exe http://192.168.1.100:8001
    echo.
) else if exist "bin\tpm_client.exe" (
    echo Executable: build\bin\tpm_client.exe
    echo.
    echo To run:
    echo   build\bin\tpm_client.exe ^<server_url^> [uuid]
    echo.
) else (
    echo Warning: Executable not found in expected location
    echo Please check build output for errors
    echo.
)

endlocal

