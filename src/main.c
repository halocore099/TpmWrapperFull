#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "tpm_wrapper.h"
#include "http_client.h"
#include "logger.h"

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
    printf("Usage: %s <server_url> [uuid]\n", program_name);
    printf("\n");
    printf("Arguments:\n");
    printf("  server_url  Backend server URL (e.g., http://192.168.1.100:8000)\n");
    printf("  uuid        Optional user UUID (if not provided, one will be generated)\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s http://192.168.1.100:8000\n", program_name);
    printf("  %s http://192.168.1.100:8000 550e8400-e29b-41d4-a716-446655440000\n", program_name);
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
    
    // Validate server URL
    if (strlen(server_url) == 0 || strlen(server_url) > 512) {
        log_error("Invalid server URL length: %zu", strlen(server_url));
        return 1;
    }
    
    if (argc >= 3) {
        if (strlen(argv[2]) >= sizeof(uuid)) {
            log_error("UUID too long: %zu characters (max: %zu)", strlen(argv[2]), sizeof(uuid) - 1);
            return 1;
        }
        strncpy(uuid, argv[2], sizeof(uuid) - 1);
        uuid[sizeof(uuid) - 1] = '\0';
    } else {
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
    if (tpm_get_attestation_data(&attest_data) != 0) {
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
    
    log_info("  EK Public Key: OK (length: %zu bytes)", strlen(attest_data.ek_pub));
    log_info("  EK Certificate: %s", attest_data.ek_cert ? "OK" : "Not available (swtpm)");
    log_info("  AIK Name: OK (length: %zu bytes)", strlen(attest_data.aik_name));
    
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
    
    // Activate credential
    log_info("Activating credential...");
    char* decrypted_secret = NULL;
    if (tpm_activate_credential(reg_response.credential_blob,
                                 reg_response.encrypted_secret,
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

