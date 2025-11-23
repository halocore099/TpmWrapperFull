cmake_minimum_required(VERSION 3.15)
project(TPMClient C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Detect platform
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(PLATFORM_WINDOWS ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_LINUX ON)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(PLATFORM_MACOS ON)
endif()

# Detect architecture
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64|AARCH64")
        set(ARCH_ARM64 ON)
        set(ARCH_NAME "arm64")
    else()
        set(ARCH_X86_64 ON)
        set(ARCH_NAME "x86_64")
    endif()
else()
    set(ARCH_X86 ON)
    set(ARCH_NAME "x86")
endif()

message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Architecture: ${ARCH_NAME}")

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs/wolfTPM)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libs/cJSON)

# Enable wolfTPM debug output to see what's happening
add_definitions(-DDEBUG_WOLFTPM)
add_definitions(-DWOLFTPM_DEBUG_VERBOSE)

# Add wolfSSL include path (for macOS Homebrew)
if(APPLE)
    if(EXISTS "/opt/homebrew/opt/wolfssl/include")
        include_directories("/opt/homebrew/opt/wolfssl/include")
    elseif(EXISTS "/usr/local/opt/wolfssl/include")
        include_directories("/usr/local/opt/wolfssl/include")
    endif()
endif()

# Find required packages
# PkgConfig is not available on Windows, so make it optional
find_package(PkgConfig)

# Find libcurl
find_package(CURL REQUIRED)
if(CURL_FOUND)
    message(STATUS "Found libcurl: ${CURL_LIBRARIES}")
    include_directories(${CURL_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "libcurl not found. Please install libcurl-dev or libcurl-devel")
endif()

# Find UUID library (for UUID generation)
if(PLATFORM_LINUX)
    find_library(UUID_LIB uuid)
    if(UUID_LIB)
        message(STATUS "Found UUID library: ${UUID_LIB}")
        set(PLATFORM_LIBS ${PLATFORM_LIBS} ${UUID_LIB})
    endif()
elseif(PLATFORM_WINDOWS)
    # Windows uses RPC for UUID (rpcrt4.lib)
    set(PLATFORM_LIBS ${PLATFORM_LIBS} rpcrt4)
endif()

# Platform-specific TPM settings
if(PLATFORM_LINUX)
    add_definitions(-DPLATFORM_LINUX)
    message(STATUS "Building for Linux - TPM via /dev/tpm0 or swtpm socket")
elseif(PLATFORM_WINDOWS)
    add_definitions(-DPLATFORM_WINDOWS)
    message(STATUS "Building for Windows - TPM via TBS API")
    set(PLATFORM_LIBS ${PLATFORM_LIBS} tbs)
elseif(PLATFORM_MACOS)
    add_definitions(-DPLATFORM_MACOS)
    message(STATUS "Building for macOS - TPM via swtpm socket")
endif()

# Download and build wolfTPM if not present
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libs/wolfTPM/CMakeLists.txt)
    message(STATUS "wolfTPM not found, will be downloaded by build script")
endif()

# Download and build cJSON if not present
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libs/cJSON/CMakeLists.txt)
    message(STATUS "cJSON not found, will be downloaded by build script")
endif()


# Add wolfTPM subdirectory if it exists
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libs/wolfTPM/CMakeLists.txt)
    # Help find wolfSSL on macOS (Homebrew)
    if(APPLE)
        if(EXISTS "/opt/homebrew/opt/wolfssl")
            list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/wolfssl")
        elseif(EXISTS "/usr/local/opt/wolfssl")
            list(APPEND CMAKE_PREFIX_PATH "/usr/local/opt/wolfssl")
        endif()
    endif()
    
    # Configure wolfTPM interface based on platform
    if(PLATFORM_WINDOWS)
        set(WOLFTPM_INTERFACE "WINAPI" CACHE STRING "TPM interface" FORCE)
        message(STATUS "Configuring wolfTPM for Windows WINAPI interface")
    elseif(APPLE)
        set(WOLFTPM_INTERFACE "SWTPM" CACHE STRING "TPM interface" FORCE)
        message(STATUS "Configuring wolfTPM for macOS SWTPM interface")
    else()
        # Linux: auto-detect (can use /dev/tpm0 or SWTPM)
        message(STATUS "Configuring wolfTPM for Linux (auto-detect interface)")
    endif()
    
    add_subdirectory(libs/wolfTPM)
    set(WOLFTPM_LIB wolftpm)
    message(STATUS "Using bundled wolfTPM")
else()
    message(WARNING "wolfTPM not found. Please run build script to download it.")
    set(WOLFTPM_LIB "")
endif()

# Add cJSON subdirectory if it exists
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libs/cJSON/CMakeLists.txt)
    add_subdirectory(libs/cJSON)
    set(CJSON_LIB cjson)
    add_definitions(-DHAVE_CJSON)
    message(STATUS "Using bundled cJSON")
else()
    message(WARNING "cJSON not found. Please run build script to download it.")
    set(CJSON_LIB "")
endif()

# Check for wolfTPM
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libs/wolfTPM/CMakeLists.txt)
    add_definitions(-DHAVE_WOLFTPM)
endif()

# Source files
set(SOURCES
    src/main.c
    src/tpm_wrapper.c
    src/platform_tpm.c
    src/http_client.c
    src/base64.c
    src/json_utils.c
    src/logger.c
    src/ek_cert_gen.c
)


# Header files
set(HEADERS
    src/tpm_wrapper.h
    src/platform_tpm.h
    src/http_client.h
    src/base64.h
    src/json_utils.h
    src/logger.h
)

# Create executable
add_executable(tpm_client ${SOURCES} ${HEADERS})


# Link libraries
target_link_libraries(tpm_client
    ${CURL_LIBRARIES}
    ${WOLFTPM_LIB}
    ${CJSON_LIB}
    ${PLATFORM_LIBS}
)


# Compiler-specific options
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tpm_client PRIVATE -Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_options(tpm_client PRIVATE -g -O0)
    else()
        target_compile_options(tpm_client PRIVATE -O2)
    endif()
endif()

# Install target
install(TARGETS tpm_client
    RUNTIME DESTINATION bin
)

message(STATUS "Build configuration complete")
message(STATUS "  Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Architecture: ${ARCH_NAME}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")

