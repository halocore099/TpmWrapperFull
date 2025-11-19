#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct cJSON;

/**
 * Build registration JSON payload
 * @param uuid User UUID
 * @param ek_pub EK public key (base64)
 * @param ek_cert EK certificate (base64, can be NULL)
 * @param aik_name AIK name (base64)
 * @return JSON string (must be freed by caller), NULL on error
 */
char* json_build_register(const char* uuid, const char* ek_pub, const char* ek_cert, const char* aik_name);

/**
 * Build challenge completion JSON payload
 * @param challenge_id Challenge ID
 * @param decrypted_secret Decrypted secret (base64)
 * @return JSON string (must be freed by caller), NULL on error
 */
char* json_build_complete_challenge(const char* challenge_id, const char* decrypted_secret);

/**
 * Parse registration response
 * @param json_str JSON response string
 * @param challenge_id Output: challenge_id (must be freed by caller)
 * @param credential_blob Output: credential_blob (must be freed by caller)
 * @param encrypted_secret Output: encrypted_secret (must be freed by caller)
 * @param hmac Output: hmac (must be freed by caller)
 * @param enc Output: enc (must be freed by caller)
 * @return 0 on success, negative on error
 */
int json_parse_register_response(const char* json_str, char** challenge_id, 
                                  char** credential_blob, char** encrypted_secret,
                                  char** hmac, char** enc);

/**
 * Parse challenge completion response
 * @param json_str JSON response string
 * @param success Output: success status
 * @param message Output: message (must be freed by caller if not NULL)
 * @return 0 on success, negative on error
 */
int json_parse_complete_response(const char* json_str, int* success, char** message);

#ifdef __cplusplus
}
#endif

#endif // JSON_UTILS_H

