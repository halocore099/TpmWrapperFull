#ifndef EK_CERT_GEN_H
#define EK_CERT_GEN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Try to read EK certificate from TPM NV storage
 * @param cert_out Output: Base64-encoded DER certificate (must be freed by caller)
 * @return 0 on success, negative on error (certificate not found)
 */
int ek_cert_read_from_nv(char** cert_out);

/**
 * Generate a test self-signed EK certificate (for testing only)
 * @param ek_pub_base64 Base64-encoded EK public key (X.509 SubjectPublicKeyInfo)
 * @return Base64-encoded DER certificate (must be freed by caller), or NULL on error
 * 
 * NOTE: This generates a test certificate with dummy signature.
 * For production, use ek_cert_read_from_nv() to get the real certificate.
 */
char* ek_cert_generate_test(const char* ek_pub_base64);

/**
 * Get EK certificate (tries NV read first, falls back to test generation)
 * @param ek_pub_base64 Base64-encoded EK public key (can be NULL if getting from Windows)
 * @return Base64-encoded DER certificate (must be freed by caller), or NULL on error
 */
char* ek_cert_get(const char* ek_pub_base64);

#ifdef PLATFORM_WINDOWS
/**
 * Get EK public key from Windows TPM Management Provider (as Administrator)
 * @param ek_pub_out Output: Base64-encoded EK public key (X.509 SubjectPublicKeyInfo)
 * @return 0 on success, negative on error
 */
int ek_pub_get_from_windows(char** ek_pub_out);

/**
 * Encode EK public key from TPM (modulus + exponent) using Windows format
 * This ensures the encoding matches exactly what Windows produces (360 bytes)
 * @param modulus RSA modulus bytes (big-endian)
 * @param modulus_len Length of modulus in bytes
 * @param exponent RSA exponent bytes (big-endian)
 * @param exponent_len Length of exponent in bytes
 * @param ek_pub_out Output: Base64-encoded EK public key (X.509 SubjectPublicKeyInfo)
 * @return 0 on success, negative on error
 */
int ek_pub_encode_from_tpm_windows(const uint8_t* modulus, size_t modulus_len,
                                   const uint8_t* exponent, size_t exponent_len,
                                   char** ek_pub_out);
#endif

#ifdef __cplusplus
}
#endif

#endif // EK_CERT_GEN_H

