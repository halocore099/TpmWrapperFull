#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode binary data to base64 string
 * @param input Binary input data
 * @param input_len Length of input data
 * @param output Output buffer (must be at least ((input_len + 2) / 3 * 4 + 1) bytes)
 * @param output_len Output buffer size
 * @return Length of encoded string (excluding null terminator), or -1 on error
 */
int base64_encode(const uint8_t* input, size_t input_len, char* output, size_t output_len);

/**
 * Decode base64 string to binary data
 * @param input Base64 input string
 * @param input_len Length of input string
 * @param output Output buffer
 * @param output_len Output buffer size
 * @return Length of decoded data, or -1 on error
 */
int base64_decode(const char* input, size_t input_len, uint8_t* output, size_t output_len);

/**
 * Calculate base64 encoded length
 * @param input_len Length of input data
 * @return Required output buffer size (including null terminator)
 */
size_t base64_encode_len(size_t input_len);

/**
 * Calculate base64 decoded length (approximate)
 * @param input_len Length of base64 string
 * @return Maximum possible decoded length
 */
size_t base64_decode_len(size_t input_len);

#ifdef __cplusplus
}
#endif

#endif // BASE64_H

