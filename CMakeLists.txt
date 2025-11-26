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

# Function to remove /Za flag from a target (MSVC fix for cJSON)
function(remove_za_flag target_name)
    if(MSVC AND TARGET ${target_name})
        # Remove from COMPILE_OPTIONS (CMake 3.0+)
        get_target_property(TARGET_OPTS ${target_name} COMPILE_OPTIONS)
        if(TARGET_OPTS)
            list(REMOVE_ITEM TARGET_OPTS "/Za")
            set_target_properties(${target_name} PROPERTIES COMPILE_OPTIONS "${TARGET_OPTS}")
        endif()
        
        # Remove from COMPILE_FLAGS (older CMake)
        get_target_property(TARGET_FLAGS ${target_name} COMPILE_FLAGS)
        if(TARGET_FLAGS)
            string(REPLACE "/Za" "" TARGET_FLAGS "${TARGET_FLAGS}")
            string(REPLACE " /Za " " " TARGET_FLAGS "${TARGET_FLAGS}")
            string(REPLACE " /Za" "" TARGET_FLAGS "${TARGET_FLAGS}")
            string(STRIP "${TARGET_FLAGS}" TARGET_FLAGS)
            set_target_properties(${target_name} PROPERTIES COMPILE_FLAGS "${TARGET_FLAGS}")
        endif()
        
        # Also remove from INTERFACE_COMPILE_OPTIONS if present
        get_target_property(TARGET_INTERFACE_OPTS ${target_name} INTERFACE_COMPILE_OPTIONS)
        if(TARGET_INTERFACE_OPTS)
            list(REMOVE_ITEM TARGET_INTERFACE_OPTS "/Za")
            set_target_properties(${target_name} PROPERTIES INTERFACE_COMPILE_OPTIONS "${TARGET_INTERFACE_OPTS}")
        endif()
    endif()
endfunction()

# Add cJSON subdirectory if it exists
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libs/cJSON/CMakeLists.txt)
    # Fix MSVC /Za conflict: cJSON's CMakeLists.txt sets /Za which conflicts with /std:c11
    if(MSVC)
        # Disable cJSON tests and utils completely (they set /Za)
        set(ENABLE_CJSON_TEST OFF CACHE BOOL "Enable cJSON testing" FORCE)
        set(ENABLE_CJSON_UTILS OFF CACHE BOOL "Enable cJSON utilities" FORCE)
    endif()
    
    add_subdirectory(libs/cJSON)
    
    # Remove /Za from all cJSON targets
    if(MSVC)
        # Fix main cJSON library
        remove_za_flag(cjson)
        
        # Fix unity target (from cJSON tests) - even if tests are disabled, it might be created
        remove_za_flag(unity)
        
        # Fix any other cJSON test targets that might exist
        remove_za_flag(cjson_test)
        remove_za_flag(print_number)
        remove_za_flag(misc_tests)
        remove_za_flag(parse_array)
        remove_za_flag(parse_examples)
        remove_za_flag(parse_hex4)
        remove_za_flag(parse_number)
        remove_za_flag(parse_object)
        remove_za_flag(parse_string)
        remove_za_flag(parse_value)
        remove_za_flag(parse_with_opts)
        remove_za_flag(compare_tests)
        remove_za_flag(json_patch_tests)
        remove_za_flag(readme_examples)
    endif()
    
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
    src/ek_cert_gen.h
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

