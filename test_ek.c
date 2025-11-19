#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tpm_wrapper.h"

int main(void) {
    printf("=== Testing tpm_get_ek() ===\n\n");
    
    // Initialize TPM wrapper
    if (tpm_wrapper_init() != 0) {
        fprintf(stderr, "Failed to initialize TPM wrapper\n");
        return 1;
    }
    
    // Get EK
    ek_data_t ek_data = {0};
    if (tpm_get_ek(&ek_data) != 0) {
        fprintf(stderr, "Failed to get EK\n");
        tpm_wrapper_cleanup();
        return 1;
    }
    
    printf("\n✓ EK retrieved successfully!\n");
    printf("EK Public Key (base64, first 80 chars): %.80s...\n", ek_data.ek_pub ? ek_data.ek_pub : "(null)");
    printf("EK Public Key length: %zu bytes\n", ek_data.ek_pub ? strlen(ek_data.ek_pub) : 0);
    
    if (ek_data.ek_cert) {
        printf("EK Certificate (base64, first 80 chars): %.80s...\n", ek_data.ek_cert);
        printf("EK Certificate length: %zu bytes\n", strlen(ek_data.ek_cert));
    } else {
        printf("EK Certificate: Not available (this is OK for swtpm)\n");
    }
    
    // Cleanup
    tpm_free_ek_data(&ek_data);
    tpm_wrapper_cleanup();
    
    printf("\n✓ Test completed successfully!\n");
    return 0;
}

