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
int platform_tpm_init(platform_tpm_ctx_t* ctx) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(platform_tpm_ctx_t));
    
    // Check TPM availability via TBS
    TBS_HCONTEXT hContext = 0;
    TBS_CONTEXT_PARAMS params = {0};
    params.version = TBS_CONTEXT_VERSION_ONE;
    
    TBS_RESULT result = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&params, &hContext);
    if (result != TBS_SUCCESS) {
        printf("Error: TPM not available (TBS error: 0x%x)\n", (unsigned int)result);
        return -1;
    }
    
    ctx->tpm_ctx = (void*)(uintptr_t)hContext;
    ctx->is_connected = false;
    printf("TPM context created successfully\n");
    return 0;
}

int platform_tpm_connect(platform_tpm_ctx_t* ctx) {
    if (!ctx || !ctx->tpm_ctx) return -1;
    
    // TBS context is already created in init
    ctx->is_connected = true;
    return 0;
}

void platform_tpm_disconnect(platform_tpm_ctx_t* ctx) {
    if (!ctx) return;
    ctx->is_connected = false;
}

void platform_tpm_cleanup(platform_tpm_ctx_t* ctx) {
    if (!ctx) return;
    
    if (ctx->tpm_ctx) {
        TBS_HCONTEXT hContext = (TBS_HCONTEXT)(uintptr_t)ctx->tpm_ctx;
        Tbsip_Context_Close(hContext);
        ctx->tpm_ctx = NULL;
    }
    ctx->is_connected = false;
}

void* platform_tpm_get_context(platform_tpm_ctx_t* ctx) {
    if (!ctx) return NULL;
    return ctx->tpm_ctx; // Return TBS context for Windows
}

bool platform_tpm_available(void) {
    TBS_HCONTEXT hContext = 0;
    TBS_CONTEXT_PARAMS params = {0};
    params.version = TBS_CONTEXT_VERSION_ONE;
    
    TBS_RESULT result = Tbsi_Context_Create((TBS_CONTEXT_PARAMS*)&params, &hContext);
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

