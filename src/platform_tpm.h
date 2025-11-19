#ifndef PLATFORM_TPM_H
#define PLATFORM_TPM_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Platform-specific TPM connection context
typedef struct {
    void* tpm_ctx;      // Platform-specific TPM context
    bool is_connected;  // Connection status
    char* device_path;  // Device path or socket path
} platform_tpm_ctx_t;

/**
 * Initialize platform-specific TPM connection
 * @param ctx Platform TPM context (output)
 * @return 0 on success, negative on error
 */
int platform_tpm_init(platform_tpm_ctx_t* ctx);

/**
 * Connect to TPM (hardware or simulator)
 * @param ctx Platform TPM context
 * @return 0 on success, negative on error
 */
int platform_tpm_connect(platform_tpm_ctx_t* ctx);

/**
 * Disconnect from TPM
 * @param ctx Platform TPM context
 */
void platform_tpm_disconnect(platform_tpm_ctx_t* ctx);

/**
 * Cleanup platform TPM resources
 * @param ctx Platform TPM context
 */
void platform_tpm_cleanup(platform_tpm_ctx_t* ctx);

/**
 * Get TPM context pointer for wolfTPM
 * @param ctx Platform TPM context
 * @return TPM context pointer (platform-specific)
 */
void* platform_tpm_get_context(platform_tpm_ctx_t* ctx);

/**
 * Check if TPM is available
 * @return true if TPM is available, false otherwise
 */
bool platform_tpm_available(void);

#ifdef __cplusplus
}
#endif

#endif // PLATFORM_TPM_H

