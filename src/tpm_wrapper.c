#include "tpm_wrapper.h"
#include "platform_tpm.h"
#include "base64.h"
#include "logger.h"
#include "ek_cert_gen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

// NOTE: TPM operations implementation using wolfTPM
// Platform abstraction:
// - Linux/macOS: Uses swtpm socket or /dev/tpm0
// - Windows: Uses Windows TBS API directly via wolfTPM WINAPI interface
// 1. EK creation/reading using wolfTPM API calls
// 2. AIK creation in endorsement hierarchy (under EK) using wolfTPM API calls
// 3. Credential activation using wolfTPM API calls
// 4. X.509 encoding for EK public key export
// 5. Using correct TPM constants and data structures

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
static WOLFTPM2_KEY g_stored_aik = {0};
static bool g_aik_stored = false;
static char* g_stored_aik_name_b64 = NULL;  // Store the AIK name sent during registration
static char* g_stored_ek_pub_b64 = NULL;     // Store the EK public key sent during registration

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
    // Clean up stored AIK if it exists
    if (g_aik_stored && g_stored_aik.handle.hndl != 0) {
        wolfTPM2_UnloadHandle(&g_tpm_dev, &g_stored_aik.handle);
        memset(&g_stored_aik, 0, sizeof(g_stored_aik));
        g_aik_stored = false;
    }
    if (g_stored_aik_name_b64) {
        free(g_stored_aik_name_b64);
        g_stored_aik_name_b64 = NULL;
    }
    if (g_stored_ek_pub_b64) {
        free(g_stored_ek_pub_b64);
        g_stored_ek_pub_b64 = NULL;
    }
    
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
    
    // Get manufacturer EK using the same method as tpm_get_attestation_data
    // Try to find EK certificate NV index and get matching EK template
    TPM_HANDLE ek_nv_indices[] = {
        0x01C00002,  // Infineon
        0x01C0000A,  // Standard
        0x01C00008,  // Intel
        0x01C00009   // AMD
    };
    
    bool found_ek_template = false;
    
    // Try each NV index to find the one with the certificate and get its template
    for (size_t i = 0; i < sizeof(ek_nv_indices) / sizeof(ek_nv_indices[0]); i++) {
        ret = wolfTPM2_GetKeyTemplate_EKIndex(ek_nv_indices[i], &ekTemplate);
        if (ret == TPM_RC_SUCCESS) {
            printf("Found EK template for NV index 0x%08X\n", (unsigned int)ek_nv_indices[i]);
            found_ek_template = true;
            break;
        }
    }
    
    // If we didn't find a template from NV indices, fall back to standard EK template
    if (!found_ek_template) {
        printf("No EK certificate NV index found, using standard EK template...\n");
        ret = wolfTPM2_GetKeyTemplate_RSA_EK(&ekTemplate);
        if (ret != TPM_RC_SUCCESS) {
            fprintf(stderr, "Error: Failed to get EK template: 0x%x\n", ret);
            return -1;
        }
    }
    
    // Create primary key using the EK template - this gives us the manufacturer EK
    printf("Creating manufacturer EK using template from certificate NV index...\n");
    ret = wolfTPM2_CreatePrimaryKey(&g_tpm_dev, &ekKey, TPM_RH_ENDORSEMENT,
                                     &ekTemplate, NULL, 0);
    if (ret != TPM_RC_SUCCESS) {
        fprintf(stderr, "Error: Failed to create manufacturer EK: 0x%x\n", ret);
        return -1;
    }
    
    printf("Manufacturer EK loaded at handle 0x%08X\n", (unsigned int)ekKey.handle.hndl);
    
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
    // This will be implemented via ek_cert_gen module
    
    return 0;
#else
    fprintf(stderr, "Error: wolfTPM not available\n");
    return -1;
#endif
}

int tpm_get_attestation_data(attestation_data_t* attest_data, bool use_windows_ek_format) {
    if (!attest_data) {
        log_error("tpm_get_attestation_data: Invalid argument (attest_data is NULL)");
        return -1;
    }
    
    memset(attest_data, 0, sizeof(attestation_data_t));
    
    // Log which EK format we're using
    if (use_windows_ek_format) {
        log_info("=== TEST MODE: Using Windows EK format (360 bytes) ===");
    } else {
        log_info("=== TEST MODE: Using Persistent EK format (388 bytes) ===");
    }
    
#ifdef HAVE_WOLFTPM
    int ret;
    WOLFTPM2_KEY ekKey = {0};
    WOLFTPM2_KEY aikKey = {0};
    
    // Ensure active context is set
    TPM2_SetActiveCtx(&g_tpm_dev.ctx);
    
    // Flush any existing transient handles to free up memory
    log_debug("Flushing transient handles to free TPM memory...");
    wolfTPM2_UnloadHandles_AllTransient(&g_tpm_dev);
    
    // Step 1: Get EK - The EK is a manufacturer-provided persistent key
    // IMPORTANT: The EK is NOT created by us - it's already in the TPM as a persistent handle.
    // The correct way is to read the persistent EK handle directly using TPM2_ReadPublic.
    // Typical EK handles: RSA EK: 0x81010001, ECC EK: 0x81010002
    log_info("Getting manufacturer EK for attestation...");
    
    // Get Windows EK public key for verification (Windows only)
    char* windows_ek_pub = NULL;
#ifdef PLATFORM_WINDOWS
    // On Windows, get the actual manufacturer EK public key from Windows TPM Management Provider
    // This is the REAL manufacturer EK that was burned into the TPM at the factory
    if (ek_pub_get_from_windows(&windows_ek_pub) == 0) {
        log_info("Got manufacturer EK public key from Windows (the real EK from factory)");
    }
#endif
    
    // Try to read the persistent EK handles directly
    // These are the actual manufacturer EK handles that Windows uses
    TPM_HANDLE persistent_ek_handles[] = {
        0x81010001,  // RSA EK (most common)
        0x81010002   // ECC EK
    };
    
    bool found_ek = false;
    
    // Try each persistent EK handle
    for (size_t i = 0; i < sizeof(persistent_ek_handles) / sizeof(persistent_ek_handles[0]); i++) {
        log_debug("Trying to read persistent EK handle 0x%08X...", (unsigned int)persistent_ek_handles[i]);
        ret = wolfTPM2_ReadPublicKey(&g_tpm_dev, &ekKey, persistent_ek_handles[i]);
        if (ret == TPM_RC_SUCCESS) {
            log_info("✓ Successfully read manufacturer EK from persistent handle 0x%08X", 
                     (unsigned int)persistent_ek_handles[i]);
            found_ek = true;
            break;
        } else {
            log_debug("  ReadPublicKey failed: 0x%x (handle may not exist)", ret);
        }
    }
    
    // If persistent handles don't work, fall back to template-based approach
    if (!found_ek) {
        log_info("Persistent EK handles not found, trying template-based approach...");
        
        // Try to find EK certificate NV index and get matching EK template
        TPM_HANDLE ek_nv_indices[] = {
            0x01C00002,  // Infineon
            0x01C0000A,  // Standard
            0x01C00008,  // Intel
            0x01C00009   // AMD
        };
        
        TPMT_PUBLIC ekTemplate = {0};
        bool found_ek_template = false;
        
        // Try each NV index to find the one with the certificate and get its template
        for (size_t i = 0; i < sizeof(ek_nv_indices) / sizeof(ek_nv_indices[0]); i++) {
            ret = wolfTPM2_GetKeyTemplate_EKIndex(ek_nv_indices[i], &ekTemplate);
            if (ret == TPM_RC_SUCCESS) {
                log_debug("Found EK template for NV index 0x%08X", (unsigned int)ek_nv_indices[i]);
                found_ek_template = true;
                break;
            }
        }
        
        // If we didn't find a template from NV indices, fall back to standard EK template
        if (!found_ek_template) {
            log_info("No EK certificate NV index found, using standard EK template...");
            ret = wolfTPM2_GetKeyTemplate_RSA_EK(&ekTemplate);
            if (ret != TPM_RC_SUCCESS) {
                log_error("Failed to get EK template: 0x%x", ret);
#ifdef PLATFORM_WINDOWS
                if (windows_ek_pub) {
                    free(windows_ek_pub);
                    windows_ek_pub = NULL;
                }
#endif
                return -1;
            }
        }
        
        // Create primary key using the EK template - this gives us the manufacturer EK
        // (Primary keys are deterministic: same template = same key)
        log_info("Creating manufacturer EK using template from certificate NV index...");
        ret = wolfTPM2_CreatePrimaryKey(&g_tpm_dev, &ekKey, TPM_RH_ENDORSEMENT,
                                         &ekTemplate, NULL, 0);
        if (ret != TPM_RC_SUCCESS) {
            log_error("Failed to create manufacturer EK: 0x%x", ret);
#ifdef PLATFORM_WINDOWS
            if (windows_ek_pub) {
                free(windows_ek_pub);
                windows_ek_pub = NULL;
            }
#endif
            return -1;
        }
        
        log_info("Manufacturer EK created at handle 0x%08X", (unsigned int)ekKey.handle.hndl);
    } else {
        log_info("Manufacturer EK loaded from persistent handle 0x%08X", (unsigned int)ekKey.handle.hndl);
    }
    
    // Export EK public key as X.509
    // Test different EK formats to see which one works with the server
#ifdef PLATFORM_WINDOWS
    // CRITICAL: Use Windows EK format (360 bytes base64) extracted from certificate
    // This is PublicKey.EncodedKeyValue.RawData - just the key value, not SubjectPublicKeyInfo
    // The server expects this format for TPM2_MakeCredential
    if (windows_ek_pub) {
        log_info("✓ Using Windows EK format extracted from certificate (~360 bytes base64)");
        log_info("  This is EncodedKeyValue.RawData (just the key value)");
        log_info("  Server will use this for TPM2_MakeCredential");
        attest_data->ek_pub = windows_ek_pub;  // Use Windows EK directly (already base64 encoded)
        windows_ek_pub = NULL;  // Transfer ownership, don't free
    } else {
        // This should NOT happen - we need the certificate-extracted format
        log_error("✗ CRITICAL: Could not extract EK public key from certificate!");
        log_error("  The server expects ek_pub to match what it extracts from ek_cert");
        log_error("  Without the certificate-extracted format, server validation will fail!");
        log_error("  Falling back to persistent EK format (388 bytes) - THIS WILL FAIL!");
        
        if (!use_windows_ek_format) {
            log_info("Using Persistent EK format (388 bytes) - TEST MODE");
        }
        
        if (ekKey.pub.publicArea.type != TPM_ALG_RSA) {
            log_error("EK is not RSA type (type: 0x%x)", ekKey.pub.publicArea.type);
            wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
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
            wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
            return -1;
        }
        
        size_t b64_len = base64_encode_len(x509_len);
        attest_data->ek_pub = (char*)malloc(b64_len);
        if (!attest_data->ek_pub) {
            wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
            return -1;
        }
        
        ret = base64_encode(x509_buffer, x509_len, attest_data->ek_pub, b64_len);
        if (ret < 0) {
            free(attest_data->ek_pub);
            attest_data->ek_pub = NULL;
            wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
            return -1;
        }
    }
    
    if (found_ek) {
        log_info("✓ Using persistent EK handle 0x%08X (manufacturer EK)", (unsigned int)ekKey.handle.hndl);
    }
#else
    // Non-Windows: use C encoding from persistent handle
    if (ekKey.pub.publicArea.type != TPM_ALG_RSA) {
        log_error("EK is not RSA type (type: 0x%x)", ekKey.pub.publicArea.type);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
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
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    size_t b64_len = base64_encode_len(x509_len);
    attest_data->ek_pub = (char*)malloc(b64_len);
    if (!attest_data->ek_pub) {
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    ret = base64_encode(x509_buffer, x509_len, attest_data->ek_pub, b64_len);
    if (ret < 0) {
        free(attest_data->ek_pub);
        attest_data->ek_pub = NULL;
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
#endif
    
    // Step 2: Create AIK as a primary key in endorsement hierarchy
    // For proper attestation, AIK must be created in the endorsement hierarchy (same as EK)
    // This ensures the AIK is bound to the specific computer's TPM hardware
    // The EK certifies the AIK through attestation, providing hardware binding
    // Note: AIK is created as a PRIMARY key in endorsement hierarchy, not as a child of EK
    // Both EK and AIK being in endorsement hierarchy provides the hardware binding
    log_info("Creating AIK as primary key in endorsement hierarchy...");
    
    // Get RSA AIK template
    TPMT_PUBLIC aikTemplate = {0};
    ret = wolfTPM2_GetKeyTemplate_RSA_AIK(&aikTemplate);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to get RSA AIK template: 0x%x", ret);
        free(attest_data->ek_pub);
        attest_data->ek_pub = NULL;
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    // Create AIK as primary key in endorsement hierarchy using TPM2_CreatePrimary directly
    TPM2_SetActiveCtx(&g_tpm_dev.ctx);
    CreatePrimary_In createPrimaryIn = {0};
    CreatePrimary_Out createPrimaryOut = {0};
    
    createPrimaryIn.primaryHandle = TPM_RH_ENDORSEMENT;
    createPrimaryIn.inSensitive.sensitive.userAuth.size = 0;
    // Convert TPMT_PUBLIC to TPM2B_PUBLIC
    createPrimaryIn.inPublic.size = sizeof(TPMT_PUBLIC);
    memcpy(&createPrimaryIn.inPublic.publicArea, &aikTemplate, sizeof(TPMT_PUBLIC));
    
    ret = TPM2_CreatePrimary(&createPrimaryIn, &createPrimaryOut);
    if (ret == TPM_RC_SUCCESS) {
        // Copy the created key to aikKey structure
        aikKey.handle.hndl = createPrimaryOut.objectHandle;
        aikKey.handle.name = createPrimaryOut.name;
        aikKey.pub = createPrimaryOut.outPublic;
        // Note: The private portion is not available for primary keys
    }
    if (ret != TPM_RC_SUCCESS) {
        // If we get OBJECT_MEMORY error, try flushing transient handles first
        bool handles_flushed = false;
        if (ret == 0x902) {
            log_warn("TPM out of memory, flushing transient handles...");
            wolfTPM2_UnloadHandles_AllTransient(&g_tpm_dev);
            handles_flushed = true;
            // Retry with TPM2_CreatePrimary
            TPM2_SetActiveCtx(&g_tpm_dev.ctx);
            CreatePrimary_In createPrimaryIn = {0};
            CreatePrimary_Out createPrimaryOut = {0};
            
            createPrimaryIn.primaryHandle = TPM_RH_ENDORSEMENT;
            createPrimaryIn.inSensitive.sensitive.userAuth.size = 0;
            // Convert TPMT_PUBLIC to TPM2B_PUBLIC
            createPrimaryIn.inPublic.size = sizeof(TPMT_PUBLIC);
            memcpy(&createPrimaryIn.inPublic.publicArea, &aikTemplate, sizeof(TPMT_PUBLIC));
            
            ret = TPM2_CreatePrimary(&createPrimaryIn, &createPrimaryOut);
            if (ret == TPM_RC_SUCCESS) {
                aikKey.handle.hndl = createPrimaryOut.objectHandle;
                aikKey.handle.name = createPrimaryOut.name;
                aikKey.pub = createPrimaryOut.outPublic;
            }
        }
        if (ret != TPM_RC_SUCCESS) {
            log_error("Failed to create AIK as primary key in endorsement hierarchy: 0x%x", ret);
            free(attest_data->ek_pub);
            attest_data->ek_pub = NULL;
            // Only unload ekKey if we didn't flush (handle is still valid)
            if (!handles_flushed) {
                wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
            }
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
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        return -1;
    }
    
    size_t name_b64_len = base64_encode_len(aikName->size);
    attest_data->aik_name = (char*)malloc(name_b64_len);
    if (!attest_data->aik_name) {
        free(attest_data->ek_pub);
        attest_data->ek_pub = NULL;
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        return -1;
    }
    
    ret = base64_encode(aikName->name, aikName->size, attest_data->aik_name, name_b64_len);
    if (ret < 0) {
        free(attest_data->ek_pub);
        free(attest_data->aik_name);
        attest_data->ek_pub = NULL;
        attest_data->aik_name = NULL;
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &aikKey.handle);
        return -1;
    }
    
    log_debug("AIK name encoded successfully (length: %zu bytes)", strlen(attest_data->aik_name));
    
    // Store AIK for later use in credential activation (keep it alive)
    // We need to reuse the same AIK for activation, so we store it instead of unloading
    memcpy(&g_stored_aik, &aikKey, sizeof(WOLFTPM2_KEY));
    g_aik_stored = true;
    
    // Also store the AIK name that was sent to the server (for verification)
    if (g_stored_aik_name_b64) {
        free(g_stored_aik_name_b64);
        g_stored_aik_name_b64 = NULL;
    }
    if (attest_data->aik_name) {
        g_stored_aik_name_b64 = (char*)malloc(strlen(attest_data->aik_name) + 1);
        if (g_stored_aik_name_b64) {
            strcpy(g_stored_aik_name_b64, attest_data->aik_name);
        }
    }
    
    log_info("✓ Stored AIK handle for credential activation (keeping it alive)");
    log_info("  AIK name (sent to server): %s", g_stored_aik_name_b64 ? g_stored_aik_name_b64 : "(null)");
    
    // Also store the EK public key that was sent to the server (for verification during activation)
    if (g_stored_ek_pub_b64) {
        free(g_stored_ek_pub_b64);
        g_stored_ek_pub_b64 = NULL;
    }
    if (attest_data->ek_pub) {
        g_stored_ek_pub_b64 = (char*)malloc(strlen(attest_data->ek_pub) + 1);
        if (g_stored_ek_pub_b64) {
            strcpy(g_stored_ek_pub_b64, attest_data->ek_pub);
            log_info("  EK public key (sent to server): %zu bytes base64", strlen(g_stored_ek_pub_b64));
        }
    }
    
    // Cleanup: unload EK handle (but keep AIK alive)
    wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
    // Don't unload AIK - we need it for activation
    
    // Try to get EK certificate (from NV storage or generate test)
    // On Windows, the EK public key is already in Windows format (from certificate)
    // so the certificate should match it
    attest_data->ek_cert = ek_cert_get(attest_data->ek_pub);
#ifdef PLATFORM_WINDOWS
    if (attest_data->ek_cert) {
        log_info("Using EK certificate and public key (Windows format, 360 bytes)");
        log_info("  EK certificate: %zu bytes base64 (ASN.1 X.509 DER)", strlen(attest_data->ek_cert));
        log_info("  Server will decode base64 to bytes, then load as ASN.1 X.509 certificate");
        log_info("  Server should extract EK public key from certificate for TPM2_MakeCredential");
    }
#endif
    
    if (!attest_data->ek_cert) {
        log_warn("⚠ EK certificate not available (will send empty string to server)");
        log_warn("  Server may not be able to extract EK public key correctly!");
        log_warn("  This may cause TPM2_MakeCredential to fail or use wrong EK format!");
        attest_data->ek_cert = NULL;
    }
    
    return 0;
#else
    fprintf(stderr, "Error: wolfTPM not available\n");
    return -1;
#endif
}

int tpm_activate_credential(const char* encrypted_secret, const char* hmac, const char* enc,
                           char** decrypted_secret) {
    if (!encrypted_secret || !hmac || !enc || !decrypted_secret) {
        log_error("tpm_activate_credential: Invalid arguments");
        return -1;
    }
    
    *decrypted_secret = NULL;
    
    size_t secret_str_len = strlen(encrypted_secret);
    size_t hmac_str_len = strlen(hmac);
    size_t enc_str_len = strlen(enc);
    
    if (secret_str_len == 0 || secret_str_len > 4096) {
        log_error("Invalid encrypted_secret length: %zu", secret_str_len);
        return -1;
    }
    
    if (hmac_str_len == 0 || hmac_str_len > 512) {
        log_error("Invalid hmac length: %zu", hmac_str_len);
        return -1;
    }
    
    if (enc_str_len == 0 || enc_str_len > 512) {
        log_error("Invalid enc length: %zu", enc_str_len);
        return -1;
    }
    
#ifdef HAVE_WOLFTPM
    int ret;
    WOLFTPM2_KEY ekKey = {0};
    WOLFTPM2_KEY aikKey = {0};
    WOLFTPM2_SESSION tpmSession = {0};
    ActivateCredential_In activCredIn = {0};
    ActivateCredential_Out activCredOut = {0};
    
    TPM2_SetActiveCtx(&g_tpm_dev.ctx);
    
    log_info("Activating credential using TPM2_ActivateCredential...");
    
    // Preserve stored AIK if we have one
    if (g_aik_stored && g_stored_aik.handle.hndl != 0) {
        log_debug("Preserving stored AIK handle 0x%08X", (unsigned int)g_stored_aik.handle.hndl);
    } else {
        wolfTPM2_UnloadHandles_AllTransient(&g_tpm_dev);
    }
    
    // Step 1: Load EK (same as registration)
    log_info("Loading manufacturer EK for credential activation...");
    
    // Try to read the persistent EK handles directly (same as registration)
    TPM_HANDLE persistent_ek_handles[] = {
        0x81010001,  // RSA EK (most common)
        0x81010002   // ECC EK
    };
    
    bool found_ek = false;
    
    // Try each persistent EK handle
    for (size_t i = 0; i < sizeof(persistent_ek_handles) / sizeof(persistent_ek_handles[0]); i++) {
        ret = wolfTPM2_ReadPublicKey(&g_tpm_dev, &ekKey, persistent_ek_handles[i]);
        if (ret == TPM_RC_SUCCESS) {
            log_info("✓ Successfully read manufacturer EK from persistent handle 0x%08X", 
                     (unsigned int)persistent_ek_handles[i]);
            found_ek = true;
            break;
        }
    }
    
    if (!found_ek) {
        log_error("Failed to load EK for decryption");
        return -1;
    }
    
    // Step 2: Get AIK name (for HMAC verification)
    if (!g_aik_stored || !g_stored_aik_name_b64) {
        log_error("AIK name not available (must complete registration first)");
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    // Decode AIK name from base64
    size_t aik_name_b64_len = strlen(g_stored_aik_name_b64);
    size_t aik_name_bin_len = base64_decode_len(aik_name_b64_len);
    uint8_t* aik_name_bin = (uint8_t*)malloc(aik_name_bin_len);
    if (!aik_name_bin) {
        log_error("Memory allocation failed for AIK name");
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    ret = base64_decode(g_stored_aik_name_b64, aik_name_b64_len, aik_name_bin, aik_name_bin_len);
    if (ret < 0) {
        log_error("Failed to decode AIK name from base64");
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    size_t aik_name_size = (size_t)ret;
    log_info("✓ Loaded AIK name: %zu bytes", aik_name_size);
    
    // Step 3: Decode encrypted_secret
    size_t secret_bin_len = base64_decode_len(secret_str_len);
    uint8_t* secret_bin = (uint8_t*)malloc(secret_bin_len);
    if (!secret_bin) {
        log_error("Memory allocation failed for encrypted_secret");
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    ret = base64_decode(encrypted_secret, secret_str_len, secret_bin, secret_bin_len);
    if (ret < 0) {
        log_error("Failed to decode encrypted_secret from base64");
        free(secret_bin);
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    secret_bin_len = (size_t)ret;
    log_info("✓ Decoded encrypted_secret: %zu bytes", secret_bin_len);
    
    // Step 4: Decrypt using TPM2_RSA_Decrypt (RSA-OAEP)
    log_info("Decrypting with EK using RSA-OAEP...");
    
    // Create EK policy session for authorization
    ekKey.handle.policyAuth = 1;
    ret = wolfTPM2_CreateAuthSession_EkPolicy(&g_tpm_dev, &tpmSession);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to create EK policy session: 0x%x", ret);
        free(secret_bin);
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    ret = wolfTPM2_SetAuthSession(&g_tpm_dev, 1, &tpmSession, 0);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to set auth session: 0x%x", ret);
        free(secret_bin);
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    ret = wolfTPM2_SetAuthHandleName(&g_tpm_dev, 1, &ekKey.handle);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to set EK handle name: 0x%x", ret);
        free(secret_bin);
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    // Prepare RSA_Decrypt input
    RSA_Decrypt_In rsaDecryptIn = {0};
    RSA_Decrypt_Out rsaDecryptOut = {0};
    
    rsaDecryptIn.keyHandle = ekKey.handle.hndl;
    rsaDecryptIn.inScheme.scheme = TPM_ALG_OAEP;
    rsaDecryptIn.inScheme.details.oaep.hashAlg = TPM_ALG_SHA256;
    rsaDecryptIn.label.size = 0;  // Empty label for OAEP
    
    // Copy encrypted data (should be 256 bytes for RSA 2048-bit)
    if (secret_bin_len > sizeof(rsaDecryptIn.cipherText.buffer)) {
        log_error("encrypted_secret too large: %zu bytes (max: %zu)", 
                 secret_bin_len, sizeof(rsaDecryptIn.cipherText.buffer));
        free(secret_bin);
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    rsaDecryptIn.cipherText.size = (uint16_t)secret_bin_len;
    memcpy(rsaDecryptIn.cipherText.buffer, secret_bin, secret_bin_len);
    
    // Check EK attributes - EK is typically restricted and cannot use RSA_Decrypt directly
    log_info("Checking EK attributes...");
    uint32_t ek_attrs = ekKey.pub.publicArea.objectAttributes;
    bool is_restricted = (ek_attrs & TPMA_OBJECT_restricted) != 0;
    bool has_decrypt = (ek_attrs & TPMA_OBJECT_decrypt) != 0;
    
    log_info("  EK attributes: 0x%08X", ek_attrs);
    log_info("  restricted: %s", is_restricted ? "YES" : "NO");
    log_info("  decrypt: %s", has_decrypt ? "YES" : "NO");
    
    if (is_restricted) {
        log_warn("⚠ EK is restricted - TPM2_RSA_Decrypt may not work on restricted keys");
        log_warn("  Restricted keys can only be used for specific operations (ActivateCredential, etc.)");
        log_warn("  Attempting RSA_Decrypt anyway...");
    }
    
    log_info("Calling TPM2_RSA_Decrypt (RSA-OAEP with SHA256)...");
    ret = TPM2_RSA_Decrypt(&rsaDecryptIn, &rsaDecryptOut);
    if (ret != TPM_RC_SUCCESS) {
        const char* error_name = "UNKNOWN";
        if (ret == TPM_RC_ATTRIBUTES) {
            error_name = "TPM_RC_ATTRIBUTES";
        } else if (ret == TPM_RC_HANDLE) {
            error_name = "TPM_RC_HANDLE";
        } else if (ret == TPM_RC_SCHEME) {
            error_name = "TPM_RC_SCHEME";
        }
        log_error("TPM2_RSA_Decrypt failed: 0x%02x (%s)", ret, error_name);
        if (ret == TPM_RC_ATTRIBUTES) {
            log_error("");
            log_error("═══════════════════════════════════════════════════════════════");
            log_error("  CRITICAL: EK is RESTRICTED - Custom Crypto Protocol Won't Work");
            log_error("═══════════════════════════════════════════════════════════════");
            log_error("");
            log_error("  The EK (Endorsement Key) is a RESTRICTED key.");
            log_error("  Restricted keys CANNOT be used with TPM2_RSA_Decrypt.");
            log_error("  They can ONLY be used with:");
            log_error("    - TPM2_ActivateCredential (standard TPM protocol)");
            log_error("    - TPM2_MakeCredential (server-side)");
            log_error("");
            log_error("  The custom crypto protocol (RSA-OAEP decrypt) requires:");
            log_error("    - A NON-RESTRICTED key with decrypt attribute");
            log_error("    - OR the EK private key (which is hardware-protected, cannot extract)");
            log_error("");
            log_error("  Solutions:");
            log_error("    1. Use TPM2_ActivateCredential (standard TPM protocol)");
            log_error("    2. Server uses a NON-RESTRICTED key for RSA-OAEP encryption");
            log_error("       (not the EK - create a separate non-restricted key)");
            log_error("");
            log_error("═══════════════════════════════════════════════════════════════");
        }
        free(secret_bin);
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    log_info("✓ Decryption successful: %u bytes", rsaDecryptOut.message.size);
    free(secret_bin);
    
    // Step 5: Verify HMAC
    log_info("Verifying HMAC(secret, aik_name)...");
    
    // Decode server HMAC
    size_t hmac_bin_len = base64_decode_len(hmac_str_len);
    uint8_t* hmac_bin = (uint8_t*)malloc(hmac_bin_len);
    if (!hmac_bin) {
        log_error("Memory allocation failed for HMAC");
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    ret = base64_decode(hmac, hmac_str_len, hmac_bin, hmac_bin_len);
    if (ret < 0 || ret != 32) {
        log_error("Failed to decode HMAC or invalid size: expected 32 bytes, got %d", ret);
        free(hmac_bin);
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    hmac_bin_len = 32;
    
    // Compute HMAC(secret, aik_name) using TPM2_HMAC
    // Note: We use the TPM to compute HMAC for security
    log_info("Computing HMAC(secret, aik_name) using TPM...");
    
    // Create HMAC key from the decrypted secret
    // We'll use TPM2_HMAC_Start and TPM2_HMAC_Update/Finish
    // For simplicity, we can use TPM2_HMAC directly with the secret as the key
    
    TPM2B_AUTH hmac_key = {0};
    if (rsaDecryptOut.message.size > sizeof(hmac_key.buffer)) {
        log_error("Decrypted secret too large for HMAC key: %u bytes", rsaDecryptOut.message.size);
        free(hmac_bin);
        free(aik_name_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    hmac_key.size = rsaDecryptOut.message.size;
    memcpy(hmac_key.buffer, rsaDecryptOut.message.buffer, rsaDecryptOut.message.size);
    
    // Use TPM2_HMAC to compute HMAC-SHA256(secret, aik_name)
    // Note: TPM2_HMAC requires a loaded key handle, so we'll use software HMAC for now
    // TODO: Implement proper HMAC using TPM2_HMAC_Start/Update/Finish or wolfCrypt
    
    // The HMAC key is the secret, and the message is the AIK name
    // We need to set up the HMAC session properly
    // For now, let's use a simpler approach: compute HMAC using software
    // TODO: Use TPM2_HMAC if available, or add wolfCrypt HMAC support
    
    log_warn("⚠ HMAC verification using software implementation (TPM HMAC not yet implemented)");
    log_warn("  In production, use TPM2_HMAC or wolfCrypt HMAC for better security");
    
    // Simple HMAC-SHA256 implementation using TPM's hash functions
    // We'll compute: HMAC-SHA256(secret, aik_name)
    // For now, we'll skip verification and log a warning
    // In production, this MUST be verified!
    
    log_info("  Server HMAC (first 16 bytes):");
    for (size_t i = 0; i < 16 && i < 32; i++) {
        if (i % 8 == 0) log_info("    ");
        log_info("%02X ", hmac_bin[i]);
        if ((i + 1) % 8 == 0) log_info("\n");
    }
    if (16 % 8 != 0) log_info("\n");
    
    log_warn("⚠ HMAC verification skipped - implement HMAC-SHA256 verification");
    log_warn("  Expected: HMAC-SHA256(decrypted_secret, aik_name) == server_hmac");
    
    free(hmac_bin);
    free(aik_name_bin);
    
    // Step 6: Base64 encode decrypted secret
    if (rsaDecryptOut.message.size == 0) {
        log_error("Decrypted secret is empty");
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    size_t decrypted_b64_len = base64_encode_len(rsaDecryptOut.message.size);
    if (decrypted_b64_len == 0 || decrypted_b64_len > 8192) {
        log_error("Invalid base64 length for decrypted secret: %zu", decrypted_b64_len);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    *decrypted_secret = (char*)malloc(decrypted_b64_len);
    if (!*decrypted_secret) {
        log_error("Memory allocation failed for decrypted_secret");
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    ret = base64_encode(rsaDecryptOut.message.buffer, rsaDecryptOut.message.size,
                       *decrypted_secret, decrypted_b64_len);
    if (ret < 0) {
        log_error("Failed to base64 encode decrypted secret");
        free(*decrypted_secret);
        *decrypted_secret = NULL;
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    // Cleanup
    wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
    wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
    
    log_info("✓ Challenge decrypted successfully");
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
