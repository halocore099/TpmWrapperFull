#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Registration response structure
typedef struct {
    char* challenge_id;
    char* credential_blob;
    char* encrypted_secret;
    char* hmac;
    char* enc;
} register_response_t;

/**
 * Initialize HTTP client
 * @return 0 on success, negative on error
 */
int http_client_init(void);

/**
 * Cleanup HTTP client
 */
void http_client_cleanup(void);

/**
 * Register with backend server
 * @param server_url Server base URL (e.g., "http://192.168.1.100:8000")
 * @param uuid User UUID
 * @param ek_pub EK public key (base64)
 * @param ek_cert EK certificate (base64, can be NULL)
 * @param aik_name AIK name (base64)
 * @param response Output: registration response (must be freed with http_free_register_response)
 * @return 0 on success, negative on error
 */
int http_register(const char* server_url, const char* uuid, const char* ek_pub, 
                  const char* ek_cert, const char* aik_name, register_response_t* response);

/**
 * Complete challenge with backend server
 * @param server_url Server base URL
 * @param challenge_id Challenge ID
 * @param decrypted_secret Decrypted secret (base64)
 * @return 0 on success, negative on error
 */
int http_complete_challenge(const char* server_url, const char* challenge_id, 
                           const char* decrypted_secret);

/**
 * Free registration response
 * @param response Response to free
 */
void http_free_register_response(register_response_t* response);

#ifdef __cplusplus
}
#endif

#endif // HTTP_CLIENT_H

