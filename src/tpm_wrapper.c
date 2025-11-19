#include "tpm_wrapper.h"
#include "platform_tpm.h"
#include "base64.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

// NOTE: This file contains placeholder implementations of TPM operations.
// The actual wolfTPM API integration needs to be completed by:
// 1. Properly configuring wolfTPM for swtpm socket connection (macOS/Linux) or TBS (Windows)
// 2. Implementing EK creation/reading using correct wolfTPM API calls
// 3. Implementing AIK creation using correct wolfTPM API calls  
// 4. Implementing credential activation using correct wolfTPM API calls
// 5. Implementing X.509 encoding for EK public key export
// 6. Using correct TPM constants and data structures

// wolfTPM includes
#ifdef HAVE_WOLFTPM
#include "wolftpm/tpm2.h"
#include "wolftpm/tpm2_types.h"
#include "wolftpm/tpm2_wrap.h"
#else
// Placeholder types if wolfTPM not available during development
typedef struct { int dummy; } WOLFTPM2_DEV;
#endif

// EK Certificate NV Index (from TCG spec)
#define EK_CERT_NV_INDEX 0x01C00002

// EK Policy (from TCG EK Credential Profile)
static const uint8_t EK_POLICY[32] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
    0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
};

static WOLFTPM2_DEV g_tpm_dev = {0};
static platform_tpm_ctx_t g_platform_ctx = {0};

// Helper function to encode ASN.1 length
static int encode_length(uint8_t* output, size_t* offset, size_t max_len, size_t len) {
    if (len < 0x80) {
        if (*offset >= max_len) return -1;
        output[(*offset)++] = (uint8_t)len;
        return 0;
    } else {
        // Multi-byte length encoding
        int bytes_needed = 0;
        size_t temp = len;
        while (temp > 0) {
            bytes_needed++;
            temp >>= 8;
        }
        if (*offset + bytes_needed + 1 > max_len) return -1;
        output[(*offset)++] = 0x80 | bytes_needed;
        for (int i = bytes_needed - 1; i >= 0; i--) {
            output[(*offset)++] = (len >> (i * 8)) & 0xFF;
        }
        return 0;
    }
}

// Helper function to encode ASN.1 INTEGER
static int encode_integer(uint8_t* output, size_t* offset, size_t max_len,
                          const uint8_t* value, size_t value_len) {
    // Skip leading zeros
    while (value_len > 1 && value[0] == 0) {
        value++;
        value_len--;
    }
    
    // If high bit is set, prepend zero byte
    int needs_padding = (value[0] & 0x80) != 0;
    size_t encoded_len = value_len + (needs_padding ? 1 : 0);
    
    if (*offset + 1 + encoded_len > max_len) return -1;
    
    output[(*offset)++] = 0x02; // INTEGER tag
    if (encode_length(output, offset, max_len, encoded_len) != 0) return -1;
    
    if (needs_padding) {
        output[(*offset)++] = 0x00;
    }
    memcpy(output + *offset, value, value_len);
    *offset += value_len;
    
    return 0;
}

// Helper function to encode RSA public key to X.509 SubjectPublicKeyInfo
static int encode_rsa_x509(const uint8_t* modulus, size_t modulus_len,
                          const uint8_t* exponent, size_t exponent_len,
                          uint8_t* output, size_t* output_len) {
    if (!modulus || !exponent || !output || !output_len) {
        return -1;
    }
    
    size_t offset = 0;
    size_t max_len = *output_len;
    
    // RSA AlgorithmIdentifier OID: 1.2.840.113549.1.1.1 (rsaEncryption)
    // Encoded as: 06 09 2A 86 48 86 F7 0D 01 01 01
    uint8_t rsa_oid[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
    // NULL parameters: 05 00
    uint8_t null_params[] = {0x05, 0x00};
    
    // AlgorithmIdentifier SEQUENCE
    uint8_t alg_id_buf[64];
    size_t alg_id_offset = 0;
    memcpy(alg_id_buf + alg_id_offset, rsa_oid, sizeof(rsa_oid));
    alg_id_offset += sizeof(rsa_oid);
    memcpy(alg_id_buf + alg_id_offset, null_params, sizeof(null_params));
    alg_id_offset += sizeof(null_params);
    
    // RSAPublicKey SEQUENCE (modulus + exponent)
    uint8_t rsa_pubkey_buf[2048];
    size_t rsa_pubkey_offset = 0;
    rsa_pubkey_buf[rsa_pubkey_offset++] = 0x30; // SEQUENCE
    size_t seq_start = rsa_pubkey_offset;
    rsa_pubkey_offset++; // Reserve space for length
    
    // Encode modulus
    if (encode_integer(rsa_pubkey_buf, &rsa_pubkey_offset, sizeof(rsa_pubkey_buf),
                      modulus, modulus_len) != 0) {
        return -1;
    }
    
    // Encode exponent
    if (encode_integer(rsa_pubkey_buf, &rsa_pubkey_offset, sizeof(rsa_pubkey_buf),
                      exponent, exponent_len) != 0) {
        return -1;
    }
    
    // Fill in SEQUENCE length
    size_t seq_len = rsa_pubkey_offset - seq_start - 1;
    if (seq_len < 0x80) {
        rsa_pubkey_buf[seq_start] = (uint8_t)seq_len;
    } else {
        // Move data and insert multi-byte length
        memmove(rsa_pubkey_buf + seq_start + 2, rsa_pubkey_buf + seq_start + 1, seq_len);
        rsa_pubkey_buf[seq_start] = 0x81;
        rsa_pubkey_buf[seq_start + 1] = (uint8_t)seq_len;
        rsa_pubkey_offset++;
    }
    
    // BitString (0 unused bits + RSAPublicKey)
    uint8_t bitstring_buf[2048];
    size_t bitstring_offset = 0;
    bitstring_buf[bitstring_offset++] = 0x03; // BIT STRING
    if (encode_length(bitstring_buf, &bitstring_offset, sizeof(bitstring_buf), rsa_pubkey_offset + 1) != 0) {
        return -1;
    }
    bitstring_buf[bitstring_offset++] = 0x00; // 0 unused bits
    memcpy(bitstring_buf + bitstring_offset, rsa_pubkey_buf, rsa_pubkey_offset);
    bitstring_offset += rsa_pubkey_offset;
    
    // SubjectPublicKeyInfo SEQUENCE
    if (offset + 1 > max_len) return -1;
    output[offset++] = 0x30; // SEQUENCE
    size_t spki_seq_start = offset;
    offset++; // Reserve space for length
    
    // AlgorithmIdentifier
    if (offset + alg_id_offset > max_len) return -1;
    memcpy(output + offset, alg_id_buf, alg_id_offset);
    offset += alg_id_offset;
    
    // SubjectPublicKey (BitString)
    if (offset + bitstring_offset > max_len) return -1;
    memcpy(output + offset, bitstring_buf, bitstring_offset);
    offset += bitstring_offset;
    
    // Fill in SEQUENCE length
    size_t spki_seq_len = offset - spki_seq_start - 1;
    if (spki_seq_len < 0x80) {
        output[spki_seq_start] = (uint8_t)spki_seq_len;
    } else {
        // Move data and insert multi-byte length
        memmove(output + spki_seq_start + 2, output + spki_seq_start + 1, spki_seq_len);
        output[spki_seq_start] = 0x81;
        output[spki_seq_start + 1] = (uint8_t)spki_seq_len;
        offset++;
    }
    
    *output_len = offset;
    return 0;
}

int tpm_wrapper_init(void) {
    int ret;
    
    // Initialize platform TPM
    ret = platform_tpm_init(&g_platform_ctx);
    if (ret != 0) {
        log_error("Failed to initialize platform TPM");
        return -1;
    }
    
    // Connect to TPM
    ret = platform_tpm_connect(&g_platform_ctx);
    if (ret != 0) {
        log_error("Failed to connect to TPM device");
        platform_tpm_cleanup(&g_platform_ctx);
        return -1;
    }
    
    // Initialize wolfTPM
#ifdef HAVE_WOLFTPM
    ret = wolfTPM2_Init(&g_tpm_dev, NULL, NULL);
    
    // For SWTPM, the TPM may return TPM_RC_INITIALIZE (0x101) which means it needs startup
    // wolfTPM2_Init uses TPM2_Init_minimal for SWTPM which doesn't send startup
    // So we need to send it manually if we get TPM_RC_INITIALIZE
    // Note: TPM_RC_INITIALIZE from TPM2_Startup means TPM is already started, which is OK
    // For SWTPM, try to reset the TPM state by sending Shutdown first, then Startup
    // This ensures the TPM is in a clean state
    log_debug("Resetting TPM state...");
    TPM2_SetActiveCtx(&g_tpm_dev.ctx);
    
    // Try Shutdown first (ignore errors - TPM might not be started)
    Shutdown_In shutdownIn;
    memset(&shutdownIn, 0, sizeof(Shutdown_In));
    shutdownIn.shutdownType = TPM_SU_CLEAR;
    int shutdown_ret = TPM2_Shutdown(&shutdownIn);
    log_debug("TPM2_Shutdown returned: 0x%x (ignoring errors)", shutdown_ret);
    
    // Now send Startup command
    log_debug("Sending TPM2_Startup command (TPM_SU_CLEAR)...");
    Startup_In startupIn;
    memset(&startupIn, 0, sizeof(Startup_In));
    startupIn.startupType = TPM_SU_CLEAR;
    
    int startup_ret = TPM2_Startup(&startupIn);
    log_debug("TPM2_Startup returned: 0x%x", startup_ret);
    
    // TPM_RC_INITIALIZE (0x101) from Startup means TPM is already started - that's OK
    // Accept both TPM_RC_INITIALIZE constant and literal 0x101
    if (startup_ret == TPM_RC_INITIALIZE || startup_ret == 0x101) {
        log_debug("TPM startup: Already initialized (this is OK)");
        startup_ret = TPM_RC_SUCCESS; // Already started is fine
    } else if (startup_ret != TPM_RC_SUCCESS) {
        log_warn("TPM2_Startup returned: 0x%x (continuing anyway)", startup_ret);
    }
    
    // If Init returned an error other than INITIALIZE, that's a problem
    if (ret != TPM_RC_SUCCESS && ret != TPM_RC_INITIALIZE && ret != 0x101) {
        // Some other error occurred
        log_error("wolfTPM2_Init failed: 0x%x (%d)", ret, ret);
        log_error("Make sure swtpm is running or TPM device is accessible");
        platform_tpm_disconnect(&g_platform_ctx);
        platform_tpm_cleanup(&g_platform_ctx);
        return -1;
    }
    
    // Ensure active context is set for subsequent operations
    TPM2_SetActiveCtx(&g_tpm_dev.ctx);
    log_debug("TPM context initialized and set as active");
    
    // Test TPM communication with a simple command
    log_debug("Testing TPM communication...");
    WOLFTPM2_CAPS caps = {0};
    ret = wolfTPM2_GetCapabilities(&g_tpm_dev, &caps);
    if (ret == TPM_RC_SUCCESS) {
        log_debug("TPM communication test successful");
    } else {
        log_warn("TPM communication test returned: 0x%x", ret);
    }
    
    const char* device_path = (const char*)platform_tpm_get_context(&g_platform_ctx);
    if (device_path) {
        log_debug("TPM device path: %s", device_path);
    }
#endif
    
    log_info("TPM wrapper initialized successfully");
    return 0;
}

void tpm_wrapper_cleanup(void) {
#ifdef HAVE_WOLFTPM
    wolfTPM2_Cleanup(&g_tpm_dev);
    memset(&g_tpm_dev, 0, sizeof(g_tpm_dev));
#endif
    
    platform_tpm_disconnect(&g_platform_ctx);
    platform_tpm_cleanup(&g_platform_ctx);
}

int tpm_get_ek(ek_data_t* ek_data) {
    if (!ek_data) {
        log_error("tpm_get_ek: Invalid argument (ek_data is NULL)");
        return -1;
    }
    
    memset(ek_data, 0, sizeof(ek_data_t));
    
#ifdef HAVE_WOLFTPM
    int ret;
    WOLFTPM2_KEY ekKey = {0};
    TPMT_PUBLIC ekTemplate = {0};
    
    // Ensure active context is set before operations
    TPM2_SetActiveCtx(&g_tpm_dev.ctx);
    
    // Try to read existing EK from endorsement hierarchy
    printf("Attempting to read existing EK from handle 0x%x...\n", TPM_RH_ENDORSEMENT);
    ret = wolfTPM2_ReadPublicKey(&g_tpm_dev, &ekKey, TPM_RH_ENDORSEMENT);
    printf("ReadPublicKey returned: 0x%x (%d)\n", ret, ret);
    
    if (ret != TPM_RC_SUCCESS) {
        // EK doesn't exist, create it using the helper function
        printf("EK not found, creating new EK...\n");
        
        ret = wolfTPM2_CreateEK(&g_tpm_dev, &ekKey, TPM_ALG_RSA);
        if (ret != TPM_RC_SUCCESS) {
            // If creation fails, try reading again - maybe it was created by another process
            if (ret == TPM_RC_INITIALIZE || ret == 0x101) {
                printf("CreateEK returned 0x101, trying to read EK again...\n");
                ret = wolfTPM2_ReadPublicKey(&g_tpm_dev, &ekKey, TPM_RH_ENDORSEMENT);
                if (ret == TPM_RC_SUCCESS) {
                    printf("Successfully read EK after creation attempt\n");
                } else {
                    fprintf(stderr, "Error: Failed to create or read EK: 0x%x\n", ret);
                    return -1;
                }
            } else {
                fprintf(stderr, "Error: Failed to create EK: 0x%x\n", ret);
                return -1;
            }
        } else {
            printf("Created new EK successfully\n");
        }
    } else {
        printf("Loaded existing EK\n");
    }
    
    // Export EK public key as X.509
    if (ekKey.pub.publicArea.type != TPM_ALG_RSA) {
        log_error("EK is not RSA type (type: 0x%x)", ekKey.pub.publicArea.type);
        return -1;
    }
    
    // Get modulus and exponent
    const TPM2B_PUBLIC_KEY_RSA* rsaKey = &ekKey.pub.publicArea.unique.rsa;
    
    // Validate RSA key size
    if (rsaKey->size == 0 || rsaKey->size > 512) {
        log_error("Invalid RSA key size: %u bytes", rsaKey->size);
        return -1;
    }
    uint32_t exponent = ekKey.pub.publicArea.parameters.rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 65537; // Default RSA exponent
    }
    
    // Convert exponent to bytes (big-endian)
    uint8_t exp_bytes[4];
    exp_bytes[0] = (exponent >> 24) & 0xFF;
    exp_bytes[1] = (exponent >> 16) & 0xFF;
    exp_bytes[2] = (exponent >> 8) & 0xFF;
    exp_bytes[3] = exponent & 0xFF;
    
    // Find actual exponent length (skip leading zeros)
    size_t exp_len = 4;
    while (exp_len > 1 && exp_bytes[4 - exp_len] == 0) {
        exp_len--;
    }
    
    // Encode to X.509
    uint8_t x509_buffer[2048];
    size_t x509_len = sizeof(x509_buffer);
    
    ret = encode_rsa_x509(rsaKey->buffer, rsaKey->size,
                         exp_bytes + (4 - exp_len), exp_len,
                         x509_buffer, &x509_len);
    
    if (ret != 0) {
        fprintf(stderr, "Error: Failed to encode EK to X.509\n");
        return -1;
    }
    
    // Base64 encode
    size_t b64_len = base64_encode_len(x509_len);
    ek_data->ek_pub = (char*)malloc(b64_len);
    if (!ek_data->ek_pub) {
        return -1;
    }
    
    ret = base64_encode(x509_buffer, x509_len, ek_data->ek_pub, b64_len);
    if (ret < 0) {
        free(ek_data->ek_pub);
        ek_data->ek_pub = NULL;
        return -1;
    }
    
    // Try to read EK certificate from NV storage (optional)
    // TODO: Implement NV read for EK certificate
    
    return 0;
#else
    fprintf(stderr, "Error: wolfTPM not available\n");
    return -1;
#endif
}

int tpm_get_attestation_data(attestation_data_t* attest_data) {
    if (!attest_data) {
        log_error("tpm_get_attestation_data: Invalid argument (attest_data is NULL)");
        return -1;
    }
    
    memset(attest_data, 0, sizeof(attestation_data_t));
    
#ifdef HAVE_WOLFTPM
    int ret;
    WOLFTPM2_KEY ekKey = {0};
    WOLFTPM2_KEY srkKey = {0};
    WOLFTPM2_KEY aikKey = {0};
    
    // Ensure active context is set
    TPM2_SetActiveCtx(&g_tpm_dev.ctx);
    
    // Flush any existing transient handles to free up memory
    log_debug("Flushing transient handles to free TPM memory...");
    wolfTPM2_UnloadHandles_AllTransient(&g_tpm_dev);
    
    // Step 1: Get EK (reuse logic from tpm_get_ek)
    log_info("Getting EK for attestation...");
    ret = wolfTPM2_ReadPublicKey(&g_tpm_dev, &ekKey, TPM_RH_ENDORSEMENT);
    
    if (ret != TPM_RC_SUCCESS) {
        log_info("EK not found, creating new EK...");
        ret = wolfTPM2_CreateEK(&g_tpm_dev, &ekKey, TPM_ALG_RSA);
        if (ret != TPM_RC_SUCCESS) {
            if (ret == TPM_RC_INITIALIZE || ret == 0x101) {
                ret = wolfTPM2_ReadPublicKey(&g_tpm_dev, &ekKey, TPM_RH_ENDORSEMENT);
                if (ret == TPM_RC_SUCCESS) {
                    log_debug("Successfully read EK after creation attempt");
                } else {
                    log_error("Failed to create or read EK: 0x%x", ret);
                    return -1;
                }
            } else {
                log_error("Failed to create EK: 0x%x", ret);
                return -1;
            }
        } else {
            log_info("Created new EK successfully");
        }
    } else {
        log_debug("Loaded existing EK");
    }
    
    // Export EK public key as X.509 (reuse from tpm_get_ek)
    if (ekKey.pub.publicArea.type != TPM_ALG_RSA) {
        log_error("EK is not RSA type (type: 0x%x)", ekKey.pub.publicArea.type);
        return -1;
    }
    
    const TPM2B_PUBLIC_KEY_RSA* rsaKey = &ekKey.pub.publicArea.unique.rsa;
    uint32_t exponent = ekKey.pub.publicArea.parameters.rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 65537;
    }
    
    uint8_t exp_bytes[4];
    exp_bytes[0] = (exponent >> 24) & 0xFF;
    exp_bytes[1] = (exponent >> 16) & 0xFF;
    exp_bytes[2] = (exponent >> 8) & 0xFF;
    exp_bytes[3] = exponent & 0xFF;
    
    size_t exp_len = 4;
    while (exp_len > 1 && exp_bytes[4 - exp_len] == 0) {
        exp_len--;
    }
    
    uint8_t x509_buffer[2048];
    size_t x509_len = sizeof(x509_buffer);
    
    ret = encode_rsa_x509(rsaKey->buffer, rsaKey->size,
                         exp_bytes + (4 - exp_len), exp_len,
                         x509_buffer, &x509_len);
    
    if (ret != 0) {
        fprintf(stderr, "Error: Failed to encode EK to X.509\n");
        return -1;
    }
    
    size_t b64_len = base64_encode_len(x509_len);
    attest_data->ek_pub = (char*)malloc(b64_len);
    if (!attest_data->ek_pub) {
        return -1;
    }
    
    ret = base64_encode(x509_buffer, x509_len, attest_data->ek_pub, b64_len);
    if (ret < 0) {
        free(attest_data->ek_pub);
        attest_data->ek_pub = NULL;
        return -1;
    }
    
    // Unload EK handle to free memory for SRK
    wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
    
    // Step 2: Create SRK (Storage Root Key) - needed as parent for AIK
    // SRK is created as a primary key under TPM_RH_OWNER, not read from a handle
    log_info("Creating SRK for AIK parent...");
    ret = wolfTPM2_CreateSRK(&g_tpm_dev, &srkKey, TPM_ALG_RSA, NULL, 0);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to create SRK: 0x%x", ret);
        free(attest_data->ek_pub);
        attest_data->ek_pub = NULL;
        return -1;
    }
    log_debug("SRK created successfully");
    
    // Step 3: Create AIK under SRK
    log_info("Creating AIK under SRK...");
    ret = wolfTPM2_CreateAndLoadAIK(&g_tpm_dev, &aikKey, TPM_ALG_RSA, &srkKey, NULL, 0);
    if (ret != TPM_RC_SUCCESS) {
        // If we get OBJECT_MEMORY error, try flushing transient handles first
        if (ret == 0x902) {
            log_warn("TPM out of memory, flushing transient handles...");
            wolfTPM2_UnloadHandles_AllTransient(&g_tpm_dev);
            ret = wolfTPM2_CreateAndLoadAIK(&g_tpm_dev, &aikKey, TPM_ALG_RSA, &srkKey, NULL, 0);
        }
        if (ret != TPM_RC_SUCCESS) {
            log_error("Failed to create AIK: 0x%x", ret);
            free(attest_data->ek_pub);
            attest_data->ek_pub = NULL;
            return -1;
        }
    }
    log_debug("AIK created successfully at handle 0x%x", (unsigned int)aikKey.handle.hndl);
    
    // Step 4: Get AIK name and base64 encode it
    const TPM2B_NAME* aikName = &aikKey.handle.name;
    if (aikName->size == 0) {
        log_error("AIK name is empty");
        free(attest_data->ek_pub);
        attest_data->ek_pub = NULL;
        return -1;
    }
    
    size_t name_b64_len = base64_encode_len(aikName->size);
    attest_data->aik_name = (char*)malloc(name_b64_len);
    if (!attest_data->aik_name) {
        free(attest_data->ek_pub);
        attest_data->ek_pub = NULL;
        return -1;
    }
    
    ret = base64_encode(aikName->name, aikName->size, attest_data->aik_name, name_b64_len);
    if (ret < 0) {
        free(attest_data->ek_pub);
        free(attest_data->aik_name);
        attest_data->ek_pub = NULL;
        attest_data->aik_name = NULL;
        return -1;
    }
    
    log_debug("AIK name encoded successfully (length: %zu bytes)", strlen(attest_data->aik_name));
    
    // EK certificate is optional (not available in swtpm)
    attest_data->ek_cert = NULL;
    
    return 0;
#else
    fprintf(stderr, "Error: wolfTPM not available\n");
    return -1;
#endif
}

int tpm_activate_credential(const char* credential_blob, const char* encrypted_secret,
                           const char* hmac, const char* enc, char** decrypted_secret) {
    if (!credential_blob || !encrypted_secret || !hmac || !enc || !decrypted_secret) {
        log_error("tpm_activate_credential: Invalid arguments");
        return -1;
    }
    
    // Validate input string lengths
    size_t cred_len = strlen(credential_blob);
    size_t secret_str_len = strlen(encrypted_secret);
    
    if (cred_len == 0 || cred_len > 4096) {
        log_error("Invalid credential_blob length: %zu", cred_len);
        return -1;
    }
    
    if (secret_str_len == 0 || secret_str_len > 4096) {
        log_error("Invalid encrypted_secret length: %zu", secret_str_len);
        return -1;
    }
    
    *decrypted_secret = NULL;
    
#ifdef HAVE_WOLFTPM
    int ret;
    WOLFTPM2_KEY ekKey = {0};
    WOLFTPM2_KEY srkKey = {0};
    WOLFTPM2_KEY aikKey = {0};
    WOLFTPM2_SESSION tpmSession = {0};
    ActivateCredential_In activCredIn = {0};
    ActivateCredential_Out activCredOut = {0};
    
    // Ensure active context is set
    TPM2_SetActiveCtx(&g_tpm_dev.ctx);
    
    // Flush transient handles to free memory
    wolfTPM2_UnloadHandles_AllTransient(&g_tpm_dev);
    
    // Step 1: Get EK (needed for credential activation)
    log_info("Loading EK for credential activation...");
    ret = wolfTPM2_ReadPublicKey(&g_tpm_dev, &ekKey, TPM_RH_ENDORSEMENT);
    if (ret != TPM_RC_SUCCESS) {
        log_info("EK not found, creating new EK...");
        ret = wolfTPM2_CreateEK(&g_tpm_dev, &ekKey, TPM_ALG_RSA);
        if (ret != TPM_RC_SUCCESS) {
            if (ret == TPM_RC_INITIALIZE || ret == 0x101) {
                ret = wolfTPM2_ReadPublicKey(&g_tpm_dev, &ekKey, TPM_RH_ENDORSEMENT);
            }
            if (ret != TPM_RC_SUCCESS) {
                log_error("Failed to get EK: 0x%x", ret);
                return -1;
            }
        }
    }
    log_debug("EK loaded");
    
    // Step 2: Get SRK (needed as parent for AIK)
    log_info("Creating SRK...");
    ret = wolfTPM2_CreateSRK(&g_tpm_dev, &srkKey, TPM_ALG_RSA, NULL, 0);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to create SRK: 0x%x", ret);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    log_debug("SRK created");
    
    // Step 3: Create AIK (needed for credential activation)
    log_info("Creating AIK for credential activation...");
    ret = wolfTPM2_CreateAndLoadAIK(&g_tpm_dev, &aikKey, TPM_ALG_RSA, &srkKey, NULL, 0);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to create AIK: 0x%x", ret);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        return -1;
    }
    log_debug("AIK created at handle 0x%x", (unsigned int)aikKey.handle.hndl);
    
    // Step 4: Set up EK policy session (EK requires policy auth for ActivateCredential)
    log_info("Creating EK policy session...");
    ekKey.handle.policyAuth = 1;
    ret = wolfTPM2_CreateAuthSession_EkPolicy(&g_tpm_dev, &tpmSession);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to create EK policy session: 0x%x", ret);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        return -1;
    }
    
    // Set the policy session for use in ActivateCredential
    ret = wolfTPM2_SetAuthSession(&g_tpm_dev, 1, &tpmSession, 0);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to set auth session: 0x%x", ret);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    // Set the name for the endorsement handle
    ret = wolfTPM2_SetAuthHandleName(&g_tpm_dev, 1, &ekKey.handle);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to set EK handle name: 0x%x", ret);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    // Step 5: Decode base64 inputs
    log_info("Decoding credential data from base64...");
    
    // Decode credential_blob (TPM2B_ID_OBJECT)
    size_t cred_blob_len = base64_decode_len(cred_len);
    uint8_t* cred_blob_buf = (uint8_t*)malloc(cred_blob_len);
    if (!cred_blob_buf) {
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    ret = base64_decode(credential_blob, cred_len, cred_blob_buf, cred_blob_len);
    if (ret >= 0) {
        cred_blob_len = (size_t)ret;
    }
    if (ret < 0) {
        log_error("Failed to decode credential_blob from base64");
        free(cred_blob_buf);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    if (cred_blob_len == 0 || cred_blob_len > sizeof(activCredIn.credentialBlob.buffer)) {
        log_error("Invalid credential_blob size: %zu (max: %zu)", cred_blob_len, sizeof(activCredIn.credentialBlob.buffer));
        free(cred_blob_buf);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    activCredIn.credentialBlob.size = (uint16_t)cred_blob_len;
    if (cred_blob_len > UINT16_MAX) {
        log_error("credential_blob size exceeds uint16_t: %zu", cred_blob_len);
        free(cred_blob_buf);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    memcpy(activCredIn.credentialBlob.buffer, cred_blob_buf, cred_blob_len);
    free(cred_blob_buf);
    
    // Decode encrypted_secret (TPM2B_ENCRYPTED_SECRET)
    size_t secret_len = base64_decode_len(secret_str_len);
    uint8_t* secret_buf = (uint8_t*)malloc(secret_len);
    if (!secret_buf) {
        log_error("Memory allocation failed for encrypted_secret");
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    ret = base64_decode(encrypted_secret, secret_str_len, secret_buf, secret_len);
    if (ret >= 0) {
        secret_len = (size_t)ret;
    }
    if (ret < 0) {
        log_error("Failed to decode encrypted_secret from base64");
        free(secret_buf);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    if (secret_len == 0 || secret_len > sizeof(activCredIn.secret.secret)) {
        log_error("Invalid encrypted_secret size: %zu (max: %zu)", secret_len, sizeof(activCredIn.secret.secret));
        free(secret_buf);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    if (secret_len > UINT16_MAX) {
        log_error("encrypted_secret size exceeds uint16_t: %zu", secret_len);
        free(secret_buf);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    activCredIn.secret.size = (uint16_t)secret_len;
    memcpy(activCredIn.secret.secret, secret_buf, secret_len);
    free(secret_buf);
    
    // Note: hmac and enc are not directly used in TPM2_ActivateCredential
    // They might be part of the credential blob structure or used for verification
    
    // Step 6: Set up ActivateCredential command
    activCredIn.activateHandle = aikKey.handle.hndl;
    activCredIn.keyHandle = ekKey.handle.hndl;
    
    // Step 7: Call TPM2_ActivateCredential
    log_info("Activating credential...");
    ret = TPM2_ActivateCredential(&activCredIn, &activCredOut);
    if (ret != TPM_RC_SUCCESS) {
        log_error("TPM2_ActivateCredential failed: 0x%x", ret);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    log_info("Credential activated successfully");
    
    // Step 8: Base64 encode the decrypted secret
    if (activCredOut.certInfo.size == 0) {
        log_error("Decrypted secret is empty");
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    if (activCredOut.certInfo.size > 4096) {
        log_error("Decrypted secret size exceeds maximum: %u", activCredOut.certInfo.size);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    size_t decrypted_b64_len = base64_encode_len(activCredOut.certInfo.size);
    if (decrypted_b64_len == 0 || decrypted_b64_len > 8192) {
        log_error("Invalid base64 length for decrypted secret: %zu", decrypted_b64_len);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    *decrypted_secret = (char*)malloc(decrypted_b64_len);
    if (!*decrypted_secret) {
        log_error("Memory allocation failed for decrypted_secret");
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    ret = base64_encode(activCredOut.certInfo.buffer, activCredOut.certInfo.size,
                       *decrypted_secret, decrypted_b64_len);
    if (ret < 0) {
        log_error("Failed to base64 encode decrypted secret");
        free(*decrypted_secret);
        *decrypted_secret = NULL;
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    // Cleanup
    tpmSession.handle.hndl = TPM_RH_NULL; // Policy session is closed after use
    wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
    wolfTPM2_UnloadHandle(&g_tpm_dev, &srkKey.handle);
    wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
    
    log_debug("Credential activation completed successfully (secret length: %zu bytes)", strlen(*decrypted_secret));
    return 0;
#else
    log_error("wolfTPM not available - rebuild with HAVE_WOLFTPM defined");
    return -1;
#endif
}

void tpm_free_ek_data(ek_data_t* ek_data) {
    if (!ek_data) return;
    
    if (ek_data->ek_pub) {
        free(ek_data->ek_pub);
        ek_data->ek_pub = NULL;
    }
    if (ek_data->ek_cert) {
        free(ek_data->ek_cert);
        ek_data->ek_cert = NULL;
    }
}

void tpm_free_attestation_data(attestation_data_t* attest_data) {
    if (!attest_data) {
        log_error("tpm_free_attestation_data: Invalid argument (attest_data is NULL)");
        return;
    }
    
    if (attest_data->ek_pub) {
        free(attest_data->ek_pub);
        attest_data->ek_pub = NULL;
    }
    if (attest_data->ek_cert) {
        free(attest_data->ek_cert);
        attest_data->ek_cert = NULL;
    }
    if (attest_data->aik_name) {
        free(attest_data->aik_name);
        attest_data->aik_name = NULL;
    }
}
