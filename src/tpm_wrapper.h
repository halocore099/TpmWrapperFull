#ifndef TPM_WRAPPER_H
#define TPM_WRAPPER_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// EK data structure
typedef struct {
    char* ek_pub;      // Base64-encoded X.509 public key
    char* ek_cert;     // Base64-encoded DER certificate (can be NULL)
} ek_data_t;

// Attestation data structure
typedef struct {
    char* ek_pub;      // Base64-encoded X.509 public key
    char* ek_cert;     // Base64-encoded DER certificate (can be NULL)
    char* aik_name;    // Base64-encoded AIK name
} attestation_data_t;

/**
 * Initialize TPM wrapper
 * @return 0 on success, negative on error
 */
int tpm_wrapper_init(void);

/**
 * Cleanup TPM wrapper
 */
void tpm_wrapper_cleanup(void);

/**
 * Get Endorsement Key (EK)
 * @param ek_data Output: EK data (must be freed with tpm_free_ek_data)
 * @return 0 on success, negative on error
 */
int tpm_get_ek(ek_data_t* ek_data);

/**
 * Get attestation data (EK + AIK)
 * @param attest_data Output: Attestation data (must be freed with tpm_free_attestation_data)
 * @param use_windows_ek_format If true, use Windows EK format (360 bytes), else use persistent EK format (388 bytes)
 * @return 0 on success, negative on error
 */
int tpm_get_attestation_data(attestation_data_t* attest_data, bool use_windows_ek_format);

/**
 * Activate credential using TPM2_ActivateCredential
 * @param encrypted_secret Base64-encoded encrypted secret (TPM2B_ENCRYPTED_SECRET)
 * @param hmac Base64-encoded HMAC (32 bytes, part of TPM2B_ID_OBJECT)
 * @param enc Base64-encoded encrypted inner credential (part of TPM2B_ID_OBJECT)
 * @param decrypted_secret Output: Base64-encoded decrypted secret (must be freed by caller)
 * @return 0 on success, negative on error
 */
int tpm_activate_credential(const char* encrypted_secret, const char* hmac, const char* enc,
                           char** decrypted_secret);

/**
 * Free EK data
 * @param ek_data EK data to free
 */
void tpm_free_ek_data(ek_data_t* ek_data);

/**
 * Free attestation data
 * @param attest_data Attestation data to free
 */
void tpm_free_attestation_data(attestation_data_t* attest_data);

#ifdef __cplusplus
}
#endif

#endif // TPM_WRAPPER_H

