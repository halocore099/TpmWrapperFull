#include "base64.h"
#include <string.h>

static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return 0; // Padding
    return -1; // Invalid
}

int base64_encode(const uint8_t* input, size_t input_len, char* output, size_t output_len) {
    if (!input || !output || output_len == 0) return -1;
    
    size_t encoded_len = base64_encode_len(input_len) - 1; // Exclude null terminator
    if (output_len < encoded_len + 1) return -1;
    
    size_t i = 0, j = 0;
    uint8_t a, b, c;
    
    for (i = 0; i < input_len; i += 3) {
        a = input[i];
        b = (i + 1 < input_len) ? input[i + 1] : 0;
        c = (i + 2 < input_len) ? input[i + 2] : 0;
        
        output[j++] = base64_chars[(a >> 2) & 0x3F];
        output[j++] = base64_chars[((a << 4) | (b >> 4)) & 0x3F];
        
        if (i + 1 < input_len) {
            output[j++] = base64_chars[((b << 2) | (c >> 6)) & 0x3F];
        } else {
            output[j++] = '=';
        }
        
        if (i + 2 < input_len) {
            output[j++] = base64_chars[c & 0x3F];
        } else {
            output[j++] = '=';
        }
    }
    
    output[j] = '\0';
    return (int)j;
}

int base64_decode(const char* input, size_t input_len, uint8_t* output, size_t output_len) {
    if (!input || !output || input_len == 0 || output_len == 0) return -1;
    
    // Remove padding
    while (input_len > 0 && input[input_len - 1] == '=') {
        input_len--;
    }
    
    size_t decoded_len = (input_len * 3) / 4;
    if (output_len < decoded_len) return -1;
    
    size_t i = 0, j = 0;
    int a, b, c, d;
    
    for (i = 0; i < input_len; i += 4) {
        a = base64_char_value(input[i]);
        b = (i + 1 < input_len) ? base64_char_value(input[i + 1]) : 0;
        c = (i + 2 < input_len) ? base64_char_value(input[i + 2]) : 0;
        d = (i + 3 < input_len) ? base64_char_value(input[i + 3]) : 0;
        
        if (a < 0 || b < 0 || c < 0 || d < 0) {
            return -1; // Invalid character
        }
        
        output[j++] = (a << 2) | (b >> 4);
        if (i + 2 < input_len) {
            output[j++] = ((b & 0x0F) << 4) | (c >> 2);
        }
        if (i + 3 < input_len) {
            output[j++] = ((c & 0x03) << 6) | d;
        }
    }
    
    return (int)j;
}

size_t base64_encode_len(size_t input_len) {
    return ((input_len + 2) / 3) * 4 + 1; // +1 for null terminator
}

size_t base64_decode_len(size_t input_len) {
    return (input_len * 3) / 4;
}

