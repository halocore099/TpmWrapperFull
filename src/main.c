#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include "tpm_wrapper.h"
#include "http_client.h"
#include "logger.h"
#include "base64.h"

#ifdef _WIN32
#include <windows.h>
#include <rpc.h>
#pragma comment(lib, "rpcrt4.lib")
#else
#include <uuid/uuid.h>
#endif

// Generate UUID string
static int generate_uuid(char* uuid_str, size_t uuid_len) {
    if (!uuid_str || uuid_len < 37) return -1;
    
#ifdef _WIN32
    UUID uuid;
    RPC_STATUS status = UuidCreate(&uuid);
    if (status != RPC_S_OK) {
        return -1;
    }
    unsigned char* str = NULL;
    UuidToStringA(&uuid, &str);
    if (!str) return -1;
    snprintf(uuid_str, uuid_len, "%s", str);
    RpcStringFreeA(&str);
#else
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, uuid_str);
#endif
    
    return 0;
}

static void print_usage(const char* program_name) {
    printf("Usage: %s <server_url> [uuid] [--ek-format=<windows|persistent>]\n", program_name);
    printf("\n");
    printf("Arguments:\n");
    printf("  server_url  Backend server URL (e.g., http://192.168.1.100:8000)\n");
    printf("  uuid        Optional user UUID (if not provided, one will be generated)\n");
    printf("  --ek-format EK format to use:\n");
    printf("               windows    - Windows EK format (360 bytes) [default]\n");
    printf("               persistent - Persistent EK format (388 bytes)\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s http://192.168.1.100:8000\n", program_name);
    printf("  %s http://192.168.1.100:8000 --ek-format=windows\n", program_name);
    printf("  %s http://192.168.1.100:8000 --ek-format=persistent\n", program_name);
}

int main(int argc, char* argv[]) {
    // Set log level based on environment variable or default to INFO
    const char* log_level_str = getenv("TPM_LOG_LEVEL");
    if (log_level_str) {
        if (strcmp(log_level_str, "DEBUG") == 0) {
            logger_set_level(LOG_LEVEL_DEBUG);
        } else if (strcmp(log_level_str, "WARN") == 0) {
            logger_set_level(LOG_LEVEL_WARN);
        } else if (strcmp(log_level_str, "ERROR") == 0) {
            logger_set_level(LOG_LEVEL_ERROR);
        } else if (strcmp(log_level_str, "NONE") == 0) {
            logger_set_level(LOG_LEVEL_NONE);
        }
    }
    
    log_info("============================================================");
    log_info("TPM Client - Registration and Attestation");
    log_info("============================================================");
    log_info("");
    
    // Parse arguments
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* server_url = argv[1];
    char uuid[37] = {0};
    bool use_windows_ek_format = true;  // Default to Windows EK format
    
    // Validate server URL
    if (strlen(server_url) == 0 || strlen(server_url) > 512) {
        log_error("Invalid server URL length: %zu", strlen(server_url));
        return 1;
    }
    
    // Parse arguments
    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], "--ek-format=", 12) == 0) {
            const char* format = argv[i] + 12;
            if (strcmp(format, "windows") == 0) {
                use_windows_ek_format = true;
                log_info("EK format: Windows (360 bytes)");
            } else if (strcmp(format, "persistent") == 0) {
                use_windows_ek_format = false;
                log_info("EK format: Persistent (388 bytes)");
            } else {
                log_error("Invalid EK format: %s (use 'windows' or 'persistent')", format);
                return 1;
            }
        } else if (strlen(uuid) == 0) {
            // Treat as UUID if not a flag
            if (strlen(argv[i]) >= sizeof(uuid)) {
                log_error("UUID too long: %zu characters (max: %zu)", strlen(argv[i]), sizeof(uuid) - 1);
                return 1;
            }
            strncpy(uuid, argv[i], sizeof(uuid) - 1);
            uuid[sizeof(uuid) - 1] = '\0';
        }
    }
    
    if (strlen(uuid) == 0) {
        // Generate UUID
        if (generate_uuid(uuid, sizeof(uuid)) != 0) {
            log_error("Failed to generate UUID");
            return 1;
        }
        log_info("Generated UUID: %s", uuid);
    }
    
    log_info("Server URL: %s", server_url);
    log_info("");
    
    // Initialize HTTP client
    log_info("Initializing HTTP client...");
    if (http_client_init() != 0) {
        log_error("Failed to initialize HTTP client");
        return 1;
    }
    
    // Initialize TPM wrapper
    log_info("Initializing TPM...");
    if (tpm_wrapper_init() != 0) {
        log_error("Failed to initialize TPM");
        http_client_cleanup();
        return 1;
    }
    
    // Get attestation data
    log_info("Getting attestation data from TPM...");
    attestation_data_t attest_data = {0};
    if (tpm_get_attestation_data(&attest_data, use_windows_ek_format) != 0) {
        log_error("Failed to get attestation data from TPM");
        log_error("Make sure TPM is available and accessible");
        tpm_wrapper_cleanup();
        http_client_cleanup();
        return 1;
    }
    
    if (!attest_data.ek_pub || !attest_data.aik_name) {
        log_error("Invalid attestation data received");
        tpm_free_attestation_data(&attest_data);
        tpm_wrapper_cleanup();
        http_client_cleanup();
        return 1;
    }
    
    log_info("  EK Public Key: OK (length: %zu bytes base64)", strlen(attest_data.ek_pub));
    if (attest_data.ek_cert) {
        log_info("  EK Certificate: OK (length: %zu bytes base64, ASN.1 X.509 DER)", strlen(attest_data.ek_cert));
        log_info("    Server will decode base64 to bytes, then load as ASN.1 X.509 certificate");
        log_info("    Server should extract EK public key from certificate for TPM2_MakeCredential");
    } else {
        log_warn("  EK Certificate: Not available (swtpm or not found)");
        log_warn("    Server may not be able to extract EK public key correctly!");
    }
    log_info("  AIK Name: OK (length: %zu bytes base64)", strlen(attest_data.aik_name));
    
    // Register with server
    log_info("Registering with server...");
    register_response_t reg_response = {0};
    if (http_register(server_url, uuid, attest_data.ek_pub, 
                     attest_data.ek_cert, attest_data.aik_name, 
                     &reg_response) != 0) {
        log_error("Registration failed");
        tpm_free_attestation_data(&attest_data);
        tpm_wrapper_cleanup();
        http_client_cleanup();
        return 1;
    }
    
    log_info("Registration successful!");
    log_info("  Challenge ID: %s", reg_response.challenge_id);
    
    // Validate credential blob and encrypted_secret before activation
    log_info("Validating credential blob and encrypted_secret...");
    if (reg_response.credential_blob && reg_response.encrypted_secret) {
        // Decode and validate credential_blob structure
        size_t cred_b64_len = strlen(reg_response.credential_blob);
        size_t cred_decoded_len = base64_decode_len(cred_b64_len);
        uint8_t* cred_decoded = (uint8_t*)malloc(cred_decoded_len);
        
        if (cred_decoded) {
            int decode_ret = base64_decode(reg_response.credential_blob, cred_b64_len, 
                                          cred_decoded, cred_decoded_len);
            if (decode_ret >= 0) {
                cred_decoded_len = (size_t)decode_ret;
                log_info("✓ credential_blob decoded successfully: %zu bytes", cred_decoded_len);
                
                // TPM2B_ID_OBJECT starts with a 2-byte size field
                if (cred_decoded_len >= 2) {
                    uint16_t cred_size = (cred_decoded[0] << 8) | cred_decoded[1];
                    log_info("  credential_blob size field: %u bytes", cred_size);
                    if (cred_size + 2 == cred_decoded_len) {
                        log_info("✓ credential_blob structure valid (size matches)");
                    } else {
                        log_warn("⚠ credential_blob size mismatch: declared %u, actual %zu", 
                                cred_size, cred_decoded_len - 2);
                    }
                    
                    // Log first few bytes for inspection
                    log_info("  credential_blob structure (first 32 bytes):");
                    size_t log_bytes = cred_decoded_len < 32 ? cred_decoded_len : 32;
                    for (size_t i = 0; i < log_bytes; i++) {
                        if (i % 16 == 0) log_info("    ");
                        log_info("%02X ", cred_decoded[i]);
                        if ((i + 1) % 16 == 0) log_info("\n");
                    }
                    if (log_bytes % 16 != 0) log_info("\n");
                } else {
                    log_warn("⚠ credential_blob too small to contain size field");
                }
            } else {
                log_error("✗ Failed to decode credential_blob from base64");
            }
            free(cred_decoded);
        }
        
        // Decode and validate encrypted_secret structure
        size_t secret_b64_len = strlen(reg_response.encrypted_secret);
        size_t secret_decoded_len = base64_decode_len(secret_b64_len);
        uint8_t* secret_decoded = (uint8_t*)malloc(secret_decoded_len);
        
        if (secret_decoded) {
            int decode_ret = base64_decode(reg_response.encrypted_secret, secret_b64_len,
                                          secret_decoded, secret_decoded_len);
            if (decode_ret >= 0) {
                secret_decoded_len = (size_t)decode_ret;
                log_info("✓ encrypted_secret decoded successfully: %zu bytes", secret_decoded_len);
                
                // Server sends encrypted_secret WITHOUT TPM2B header (for tss.net compatibility)
                // We'll add the header in tpm_wrapper.c for wolfTPM compatibility
                if (secret_decoded_len == 256) {
                    log_info("✓ encrypted_secret: 256 bytes (raw data, no TPM2B header)");
                    log_info("  Server strips header for tss.net compatibility");
                    log_info("  Client will add TPM2B header (0x0100) for wolfTPM");
                } else if (secret_decoded_len == 258) {
                    // Server sent with header (unlikely but handle it)
                    uint16_t secret_size = (secret_decoded[0] << 8) | secret_decoded[1];
                    if (secret_size == 256) {
                        log_info("✓ encrypted_secret: 258 bytes (with TPM2B header)");
                        log_info("  Size field: 0x%04X (256 bytes) - correct", secret_size);
                    } else {
                        log_warn("⚠ encrypted_secret: 258 bytes but size field is 0x%04X (expected 0x0100)", secret_size);
                    }
                } else if (secret_decoded_len >= 2) {
                    // Unexpected size - check if first 2 bytes look like encrypted data
                    uint16_t first_two_bytes = (secret_decoded[0] << 8) | secret_decoded[1];
                    if (first_two_bytes > 256) {
                        log_info("✓ encrypted_secret: %zu bytes (raw data, no TPM2B header)", secret_decoded_len);
                        log_info("  First 2 bytes (0x%04X) are encrypted data, not size field", first_two_bytes);
                        log_info("  Client will add TPM2B header for wolfTPM");
                    } else {
                        log_warn("⚠ encrypted_secret: unexpected size %zu bytes", secret_decoded_len);
                    }
                } else {
                    log_warn("⚠ encrypted_secret too small: %zu bytes", secret_decoded_len);
                }
                
                // Log first few bytes for inspection
                if (secret_decoded_len > 0) {
                    log_info("  encrypted_secret structure (first 32 bytes):");
                    size_t log_bytes = secret_decoded_len < 32 ? secret_decoded_len : 32;
                    for (size_t i = 0; i < log_bytes; i++) {
                        if (i % 16 == 0) log_info("    ");
                        log_info("%02X ", secret_decoded[i]);
                        if ((i + 1) % 16 == 0) log_info("\n");
                    }
                    if (log_bytes % 16 != 0) log_info("\n");
                }
            } else {
                log_error("✗ Failed to decode encrypted_secret from base64");
            }
            free(secret_decoded);
        }
    } else {
        log_error("✗ Missing credential_blob or encrypted_secret in server response");
    }
    log_info("");
    
    // Activate credential
    log_info("Activating credential...");
    char* decrypted_secret = NULL;
    if (tpm_activate_credential(reg_response.encrypted_secret,
                                reg_response.hmac,
                                reg_response.enc,
                                &decrypted_secret) != 0) {
        log_error("Failed to activate credential");
        http_free_register_response(&reg_response);
        tpm_free_attestation_data(&attest_data);
        tpm_wrapper_cleanup();
        http_client_cleanup();
        return 1;
    }
    
    log_info("Credential activated successfully!");
    
    // Complete challenge
    log_info("Completing challenge...");
    if (http_complete_challenge(server_url, reg_response.challenge_id, 
                               decrypted_secret) != 0) {
        log_error("Failed to complete challenge");
        free(decrypted_secret);
        http_free_register_response(&reg_response);
        tpm_free_attestation_data(&attest_data);
        tpm_wrapper_cleanup();
        http_client_cleanup();
        return 1;
    }
    
    log_info("Challenge completed successfully!");
    
    // Cleanup
    free(decrypted_secret);
    http_free_register_response(&reg_response);
    tpm_free_attestation_data(&attest_data);
    tpm_wrapper_cleanup();
    http_client_cleanup();
    
    log_info("");
    log_info("============================================================");
    log_info("SUCCESS: Registration and attestation complete!");
    log_info("============================================================");
    
    return 0;
}

