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

REM Check for vcpkg toolchain
set VCPKG_TOOLCHAIN=

REM Try C:\vcpkg first (most common location)
if exist C:\vcpkg\scripts\buildsystems\vcpkg.cmake (
    set VCPKG_TOOLCHAIN=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
    echo Found vcpkg toolchain: C:\vcpkg\scripts\buildsystems\vcpkg.cmake
    goto :skip_vcpkg_check
)

REM Check VCPKG_ROOT environment variable if C:\vcpkg not found
if defined VCPKG_ROOT (
    set "VCPKG_CHECK=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
    if exist "!VCPKG_CHECK!" (
        set VCPKG_TOOLCHAIN=!VCPKG_CHECK!
        echo Found vcpkg toolchain: !VCPKG_TOOLCHAIN!
        goto :skip_vcpkg_check
    )
)

REM Try user profile location if still not found
set "VCPKG_CHECK=%USERPROFILE%\vcpkg\scripts\buildsystems\vcpkg.cmake"
if exist "!VCPKG_CHECK!" (
    set VCPKG_TOOLCHAIN=!VCPKG_CHECK!
    echo Found vcpkg toolchain: !VCPKG_TOOLCHAIN!
    goto :skip_vcpkg_check
)

REM Skip LOCALAPPDATA check to avoid "Microsoft" parsing issues
REM If vcpkg is not in standard locations, user should set VCPKG_ROOT

:skip_vcpkg_check

REM Check for libcurl
echo Checking for libcurl...
where curl.exe >nul 2>&1
if errorlevel 1 (
    echo Warning: curl.exe not found in PATH
    echo This is OK if libcurl is installed via vcpkg or other package manager
)
if not defined VCPKG_TOOLCHAIN (
    echo.
    echo Warning: vcpkg toolchain not found!
    echo libcurl should be installed via one of:
    echo   - vcpkg: vcpkg install curl:x64-windows
    echo   - Pre-built binaries from curl.se
    echo   - Visual Studio vcpkg integration
    echo.
    echo If using vcpkg, set VCPKG_ROOT environment variable or install vcpkg to C:\vcpkg
    echo.
) else (
    echo vcpkg toolchain will be used for finding dependencies
    echo.
)

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

REM Fix cJSON CMakeLists.txt issues: Remove /Za flag and update cmake_minimum_required
if exist "libs\cJSON\CMakeLists.txt" (
    echo Fixing cJSON CMakeLists.txt...
    powershell -NoProfile -Command "$file = 'libs\cJSON\CMakeLists.txt'; $content = Get-Content $file -Raw; $content = $content -replace '/Za', ''; $content = $content -replace ' /Za ', ' '; $content = $content -replace ' /Za', ''; $content = $content -replace 'cmake_minimum_required\s*\(\s*VERSION\s+[0-9.]+\s*\)', 'cmake_minimum_required(VERSION 3.5)'; Set-Content $file -Value $content -NoNewline"
    if errorlevel 1 (
        echo Warning: PowerShell patch failed, trying manual sed-like replacement...
        REM Fallback: Use a simpler approach
        powershell -NoProfile -Command "$lines = Get-Content 'libs\cJSON\CMakeLists.txt'; $newLines = $lines | ForEach-Object { if ($_ -match 'cmake_minimum_required') { 'cmake_minimum_required(VERSION 3.5)' } else { $_ -replace '/Za', '' -replace ' /Za ', ' ' -replace ' /Za', '' } }; Set-Content 'libs\cJSON\CMakeLists.txt' -Value $newLines"
        if errorlevel 1 (
            echo Warning: Failed to patch cJSON CMakeLists.txt automatically
            echo Please manually edit libs\cJSON\CMakeLists.txt:
            echo   1. Change cmake_minimum_required to VERSION 3.5 or higher
            echo   2. Remove all /Za flags
        ) else (
            echo cJSON CMakeLists.txt patched successfully
        )
    ) else (
        echo cJSON CMakeLists.txt patched successfully
    )
)


echo.

REM Create build directory
echo Creating build directory...
if not exist build mkdir build
cd build

REM Clean build directory if CMakeCache exists and might conflict
if exist CMakeCache.txt (
    echo Cleaning previous CMake configuration...
    del /q CMakeCache.txt 2>nul
    if exist CMakeFiles rmdir /s /q CMakeFiles 2>nul
)

REM Configure CMake
echo Configuring CMake...
REM Build CMake command with vcpkg toolchain if available
if defined VCPKG_TOOLCHAIN (
    set CMAKE_CMD=cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=%VCPKG_TOOLCHAIN%
) else (
    set CMAKE_CMD=cmake .. -DCMAKE_BUILD_TYPE=Release
)

REM Try Visual Studio 2022 first, then 2019, then default
%CMAKE_CMD% -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo Visual Studio 2022 not found, trying Visual Studio 2019...
    %CMAKE_CMD% -G "Visual Studio 16 2019" -A x64
    if errorlevel 1 (
        echo Visual Studio 2019 not found, trying default generator...
        %CMAKE_CMD%
        if errorlevel 1 (
            echo Error: CMake configuration failed
            echo.
            echo Please ensure:
            echo   1. CMake is installed and in PATH
            echo   2. Visual Studio 2019 or 2022 is installed (with C++ tools)
            echo   3. libcurl is available (via vcpkg or pre-built)
            if not defined VCPKG_TOOLCHAIN (
                echo   4. vcpkg is installed and VCPKG_ROOT is set, or vcpkg is at C:\vcpkg
            )
            echo   5. Git is installed (for downloading dependencies)
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

