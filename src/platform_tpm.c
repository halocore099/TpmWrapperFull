#include "platform_tpm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef PLATFORM_LINUX
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#elif defined(PLATFORM_WINDOWS)
#include <windows.h>
#include <tbs.h>
#include <stdbool.h>

// TBS_CONTEXT_PARAMS2 is defined in Windows SDK tbs.h
// It has: version (UINT32) and includeTpm20 (BOOL) fields
// TBS_CONTEXT_VERSION_TWO and TBS_CONTEXT_CREATE_FLAGS_INCLUDE_TPM20 are also in tbs.h
#elif defined(PLATFORM_MACOS)
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#endif

// Helper function to check if TPM device/socket exists
static bool check_tpm_device(const char* path) {
#ifdef PLATFORM_WINDOWS
    // Windows: Use GetFileAttributes to check if file exists
    DWORD dwAttrib = GetFileAttributesA(path);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
            !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
#else
    // Unix/Linux/macOS: Use access()
    return access(path, F_OK) == 0;
#endif
}

#ifdef PLATFORM_LINUX
// Linux: Use /dev/tpm0 or swtpm socket

int platform_tpm_init(platform_tpm_ctx_t* ctx) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(platform_tpm_ctx_t));
    
    // Try hardware TPM first
    if (check_tpm_device("/dev/tpm0")) {
        ctx->device_path = strdup("/dev/tpm0");
        printf("Found hardware TPM at /dev/tpm0\n");
        return 0;
    }
    
    // Try swtpm socket
    if (check_tpm_device("/tmp/swtpm-sock")) {
        ctx->device_path = strdup("/tmp/swtpm-sock");
        printf("Found swtpm socket at /tmp/swtpm-sock\n");
        return 0;
    }
    
    // No TPM found
    printf("Warning: No TPM device found. Tried /dev/tpm0 and /tmp/swtpm-sock\n");
    return -1;
}

int platform_tpm_connect(platform_tpm_ctx_t* ctx) {
    if (!ctx || !ctx->device_path) return -1;
    
    // For Linux, wolfTPM will handle the connection
    // We just need to provide the device path
    ctx->is_connected = true;
    return 0;
}

void platform_tpm_disconnect(platform_tpm_ctx_t* ctx) {
    if (!ctx) return;
    ctx->is_connected = false;
}

void platform_tpm_cleanup(platform_tpm_ctx_t* ctx) {
    if (!ctx) return;
    
    if (ctx->device_path) {
        free(ctx->device_path);
        ctx->device_path = NULL;
    }
    ctx->is_connected = false;
}

void* platform_tpm_get_context(platform_tpm_ctx_t* ctx) {
    if (!ctx) return NULL;
    return ctx->device_path; // Return device path for Linux
}

bool platform_tpm_available(void) {
    return check_tpm_device("/dev/tpm0") || check_tpm_device("/tmp/swtpm-sock");
}

#elif defined(PLATFORM_WINDOWS)
// Windows: Use TBS (TPM Base Services)
// Note: wolfTPM's WINAPI interface creates its own TBS context internally,
// so we just verify TBS is available without creating a persistent context.
int platform_tpm_init(platform_tpm_ctx_t* ctx) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(platform_tpm_ctx_t));
    
    // Verify TBS is available by creating a test context and immediately closing it
    // wolfTPM will create its own TBS context when needed
    TBS_HCONTEXT hContext = 0;
    TBS_RESULT result = TBS_E_INTERNAL_ERROR;
    
    // Try TBS_CONTEXT_VERSION_TWO first (for TPM 2.0)
    #ifdef TBS_CONTEXT_VERSION_TWO
    TBS_CONTEXT_PARAMS2 params2 = {0};
    params2.version = TBS_CONTEXT_VERSION_TWO;
    params2.includeTpm20 = TRUE;
    result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params2, &hContext);
    #endif
    
    // If version 2 not available or failed, try version 1
    if (result != TBS_SUCCESS) {
        TBS_CONTEXT_PARAMS params = {0};
        params.version = TBS_CONTEXT_VERSION_ONE;
        result = Tbsi_Context_Create(&params, &hContext);
    }
    
    if (result != TBS_SUCCESS) {
        printf("Error: TPM not available (TBS error: 0x%x)\n", (unsigned int)result);
        return -1;
    }
    
    // Close the test context - wolfTPM will create its own when needed
    Tbsip_Context_Close(hContext);
    
    // Don't store context - wolfTPM WINAPI creates its own
    ctx->tpm_ctx = NULL;
    ctx->is_connected = false;
    printf("TPM available (TBS verified, wolfTPM will create its own context)\n");
    return 0;
}

int platform_tpm_connect(platform_tpm_ctx_t* ctx) {
    if (!ctx) return -1;
    
    // For Windows, wolfTPM creates its own TBS context, so we just mark as connected
    ctx->is_connected = true;
    return 0;
}

void platform_tpm_disconnect(platform_tpm_ctx_t* ctx) {
    if (!ctx) return;
    ctx->is_connected = false;
}

void platform_tpm_cleanup(platform_tpm_ctx_t* ctx) {
    if (!ctx) return;
    
    // For Windows, wolfTPM manages its own TBS context, so nothing to clean up here
    ctx->tpm_ctx = NULL;
    ctx->is_connected = false;
}

void* platform_tpm_get_context(platform_tpm_ctx_t* ctx) {
    if (!ctx) return NULL;
    return ctx->tpm_ctx; // Return TBS context for Windows
}

bool platform_tpm_available(void) {
    TBS_HCONTEXT hContext = 0;
    TBS_RESULT result = TBS_E_INTERNAL_ERROR;
    
    // Try TBS_CONTEXT_VERSION_TWO first (for TPM 2.0)
    #ifdef TBS_CONTEXT_VERSION_TWO
    TBS_CONTEXT_PARAMS2 params2 = {0};
    params2.version = TBS_CONTEXT_VERSION_TWO;
    params2.includeTpm20 = TRUE;
    result = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params2, &hContext);
    #endif
    
    // If version 2 not available or failed, try version 1
    if (result != TBS_SUCCESS) {
        TBS_CONTEXT_PARAMS params = {0};
        params.version = TBS_CONTEXT_VERSION_ONE;
        result = Tbsi_Context_Create(&params, &hContext);
    }
    if (result == TBS_SUCCESS) {
        Tbsip_Context_Close(hContext);
        return true;
    }
    return false;
}

#elif defined(PLATFORM_MACOS)
// macOS: Use swtpm socket (for development)
int platform_tpm_init(platform_tpm_ctx_t* ctx) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(platform_tpm_ctx_t));
    
    // Check for swtpm socket
    if (check_tpm_device("/tmp/swtpm-sock")) {
        ctx->device_path = strdup("/tmp/swtpm-sock");
        printf("Found swtpm socket at /tmp/swtpm-sock\n");
        return 0;
    }
    
    printf("Warning: swtpm socket not found at /tmp/swtpm-sock\n");
    printf("Please start swtpm: swtpm socket --tpm2 --port 2321 --ctrl type=unixio,path=/tmp/swtpm-sock\n");
    return -1;
}

int platform_tpm_connect(platform_tpm_ctx_t* ctx) {
    if (!ctx || !ctx->device_path) return -1;
    
    ctx->is_connected = true;
    return 0;
}

void platform_tpm_disconnect(platform_tpm_ctx_t* ctx) {
    if (!ctx) return;
    ctx->is_connected = false;
}

void platform_tpm_cleanup(platform_tpm_ctx_t* ctx) {
    if (!ctx) return;
    
    if (ctx->device_path) {
        free(ctx->device_path);
        ctx->device_path = NULL;
    }
    ctx->is_connected = false;
}

void* platform_tpm_get_context(platform_tpm_ctx_t* ctx) {
    if (!ctx) return NULL;
    return ctx->device_path; // Return socket path for macOS
}

bool platform_tpm_available(void) {
    return check_tpm_device("/tmp/swtpm-sock");
}

#else
#error "Unsupported platform"
#endif

