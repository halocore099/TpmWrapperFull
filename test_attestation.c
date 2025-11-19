#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tpm_wrapper.h"

int main(void) {
    printf("=== Testing tpm_get_attestation_data() ===\n\n");
    
    // Initialize TPM wrapper
    if (tpm_wrapper_init() != 0) {
        fprintf(stderr, "Failed to initialize TPM wrapper\n");
        return 1;
    }
    
    // Get attestation data
    attestation_data_t attest_data = {0};
    if (tpm_get_attestation_data(&attest_data) != 0) {
        fprintf(stderr, "Failed to get attestation data\n");
        tpm_wrapper_cleanup();
        return 1;
    }
    
    printf("\n✓ Attestation data retrieved successfully!\n");
    printf("EK Public Key (base64, first 80 chars): %.80s...\n", 
           attest_data.ek_pub ? attest_data.ek_pub : "(null)");
    printf("EK Public Key length: %zu bytes\n", 
           attest_data.ek_pub ? strlen(attest_data.ek_pub) : 0);
    
    if (attest_data.ek_cert) {
        printf("EK Certificate (base64, first 80 chars): %.80s...\n", attest_data.ek_cert);
        printf("EK Certificate length: %zu bytes\n", strlen(attest_data.ek_cert));
    } else {
        printf("EK Certificate: Not available (this is OK for swtpm)\n");
    }
    
    printf("AIK Name (base64, first 80 chars): %.80s...\n", 
           attest_data.aik_name ? attest_data.aik_name : "(null)");
    printf("AIK Name length: %zu bytes\n", 
           attest_data.aik_name ? strlen(attest_data.aik_name) : 0);
    
    // Cleanup
    tpm_free_attestation_data(&attest_data);
    tpm_wrapper_cleanup();
    
    printf("\n✓ Test completed successfully!\n");
    return 0;
}

