#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "tpm_wrapper.h"
#include "json_utils.h"

// Response buffer for curl
typedef struct {
    char* data;
    size_t size;
} response_buffer_t;

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    response_buffer_t* mem = (response_buffer_t*)userp;
    
    char* ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) return 0;
    
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    
    return realsize;
}

int main(void) {
    const char* server_url = "http://170.205.26.102:8001";
    
    printf("============================================================\n");
    printf("Automated Server Debugging Test\n");
    printf("============================================================\n\n");
    
    // Initialize TPM
    printf("Step 1: Initializing TPM...\n");
    if (tpm_wrapper_init() != 0) {
        fprintf(stderr, "❌ Failed to initialize TPM\n");
        return 1;
    }
    
    // Get attestation data
    printf("Step 2: Getting attestation data...\n");
    attestation_data_t attest_data = {0};
    if (tpm_get_attestation_data(&attest_data) != 0) {
        fprintf(stderr, "❌ Failed to get attestation data\n");
        tpm_wrapper_cleanup();
        return 1;
    }
    
    if (!attest_data.ek_pub || !attest_data.aik_name) {
        fprintf(stderr, "❌ Invalid attestation data\n");
        tpm_free_attestation_data(&attest_data);
        tpm_wrapper_cleanup();
        return 1;
    }
    
    printf("✓ EK Public Key: %.50s... (length: %zu)\n", attest_data.ek_pub, strlen(attest_data.ek_pub));
    printf("✓ AIK Name: %.50s... (length: %zu)\n", attest_data.aik_name, strlen(attest_data.aik_name));
    printf("\n");
    
    // Generate UUID
    char uuid[37];
    #ifdef __APPLE__
    FILE* uuidgen = popen("uuidgen", "r");
    if (uuidgen) {
        fgets(uuid, sizeof(uuid), uuidgen);
        pclose(uuidgen);
        uuid[strcspn(uuid, "\n")] = 0;
    } else {
        strcpy(uuid, "test-uuid-1234");
    }
    #else
    strcpy(uuid, "test-uuid-1234");
    #endif
    
    printf("Step 3: Generated UUID: %s\n", uuid);
    printf("\n");
    
    // Build JSON
    printf("Step 4: Building registration JSON...\n");
    char* json_payload = json_build_register(uuid, attest_data.ek_pub, 
                                             attest_data.ek_cert, attest_data.aik_name);
    if (!json_payload) {
        fprintf(stderr, "❌ Failed to build JSON\n");
        tpm_free_attestation_data(&attest_data);
        tpm_wrapper_cleanup();
        return 1;
    }
    
    printf("JSON Payload:\n%s\n\n", json_payload);
    
    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL* curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "❌ Failed to initialize curl\n");
        free(json_payload);
        tpm_free_attestation_data(&attest_data);
        tpm_wrapper_cleanup();
        return 1;
    }
    
    // Build URL
    char url[512];
    snprintf(url, sizeof(url), "%s/register", server_url);
    
    response_buffer_t buffer = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    printf("Step 5: Sending registration request to %s...\n", url);
    CURLcode res = curl_easy_perform(curl);
    
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    printf("\nHTTP Status Code: %ld\n", response_code);
    printf("Response Body:\n%s\n", buffer.data ? buffer.data : "(empty)");
    
    if (buffer.data) free(buffer.data);
    free(json_payload);
    tpm_free_attestation_data(&attest_data);
    tpm_wrapper_cleanup();
    
    if (response_code == 200) {
        printf("\n✅ Registration successful!\n");
        return 0;
    } else {
        printf("\n❌ Registration failed\n");
        return 1;
    }
}

