#include "http_client.h"
#include "json_utils.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <errno.h>

#define HTTP_TIMEOUT 30

// Response buffer structure for curl
typedef struct {
    char* data;
    size_t size;
} response_buffer_t;

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    response_buffer_t* mem = (response_buffer_t*)userp;
    
    char* ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        return 0; // Out of memory
    }
    
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    
    return realsize;
}

int http_client_init(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    return 0;
}

void http_client_cleanup(void) {
    curl_global_cleanup();
}

int http_register(const char* server_url, const char* uuid, const char* ek_pub, 
                  const char* ek_cert, const char* aik_name, register_response_t* response) {
    if (!server_url || !uuid || !ek_pub || !aik_name || !response) {
        return -1;
    }
    
    memset(response, 0, sizeof(register_response_t));
    
    // Build JSON payload
    char* json_payload = json_build_register(uuid, ek_pub, ek_cert, aik_name);
    if (!json_payload) {
        fprintf(stderr, "Error: Failed to build registration JSON\n");
        return -1;
    }
    
    // Build URL
    char url[512];
    snprintf(url, sizeof(url), "%s/register", server_url);
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        free(json_payload);
        return -1;
    }
    
    response_buffer_t buffer = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_TIMEOUT);
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(json_payload);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        if (buffer.data) free(buffer.data);
        return -1;
    }
    
    if (response_code != 200) {
        fprintf(stderr, "Error: Server returned HTTP %ld\n", response_code);
        if (buffer.data) {
            fprintf(stderr, "Response: %s\n", buffer.data);
            free(buffer.data);
        }
        return -1;
    }
    
    if (!buffer.data) {
        fprintf(stderr, "Error: Empty response from server\n");
        return -1;
    }
    
    // Log the full server response for debugging
    log_info("=== Server Registration Response ===");
    log_info("Full JSON response:");
    log_info("%s", buffer.data);
    log_info("=== End of Server Response ===");
    
    // Parse response
    int parse_result = json_parse_register_response(buffer.data, 
        &response->challenge_id,
        &response->credential_blob,
        &response->encrypted_secret,
        &response->hmac,
        &response->enc,
        &response->hwid,
        &response->ek_hash);
    
    free(buffer.data);
    
    if (parse_result != 0) {
        fprintf(stderr, "Error: Failed to parse server response\n");
        http_free_register_response(response);
        return -1;
    }
    
    // Log parsed response fields
    log_info("=== Parsed Registration Response ===");
    log_info("  challenge_id: %s", response->challenge_id ? response->challenge_id : "(null)");
    log_info("  credential_blob: %s (%zu bytes)", 
             response->credential_blob ? "present" : "(null)",
             response->credential_blob ? strlen(response->credential_blob) : 0);
    log_info("  encrypted_secret: %s (%zu bytes)",
             response->encrypted_secret ? "present" : "(null)",
             response->encrypted_secret ? strlen(response->encrypted_secret) : 0);
    log_info("  hmac: %s (%zu bytes)",
             response->hmac ? "present" : "(null)",
             response->hmac ? strlen(response->hmac) : 0);
    log_info("  enc: %s (%zu bytes)",
             response->enc ? "present" : "(null)",
             response->enc ? strlen(response->enc) : 0);
    log_info("  hwid: %s (%zu bytes)",
             response->hwid ? "present" : "(null)",
             response->hwid ? strlen(response->hwid) : 0);
    log_info("  ek_hash: %s",
             response->ek_hash ? response->ek_hash : "(null)");
    log_info("=== End of Parsed Response ===");
    
    return 0;
}

int http_complete_challenge(const char* server_url, const char* challenge_id, 
                           const char* decrypted_secret) {
    if (!server_url || !challenge_id || !decrypted_secret) {
        return -1;
    }
    
    // Build JSON payload
    char* json_payload = json_build_complete_challenge(challenge_id, decrypted_secret);
    if (!json_payload) {
        fprintf(stderr, "Error: Failed to build challenge completion JSON\n");
        return -1;
    }
    
    // Build URL
    char url[512];
    snprintf(url, sizeof(url), "%s/completeChallenge", server_url);
    
    CURL* curl = curl_easy_init();
    if (!curl) {
        free(json_payload);
        return -1;
    }
    
    response_buffer_t buffer = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, HTTP_TIMEOUT);
    
    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(json_payload);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "Error: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        if (buffer.data) free(buffer.data);
        return -1;
    }
    
    if (response_code != 200) {
        fprintf(stderr, "Error: Server returned HTTP %ld\n", response_code);
        if (buffer.data) {
            fprintf(stderr, "Response: %s\n", buffer.data);
            free(buffer.data);
        }
        return -1;
    }
    
    int success = 0;
    char* message = NULL;
    json_parse_complete_response(buffer.data, &success, &message);
    
    if (buffer.data) free(buffer.data);
    if (message) free(message);
    
    if (!success) {
        fprintf(stderr, "Error: Challenge completion failed\n");
        return -1;
    }
    
    return 0;
}

void http_free_register_response(register_response_t* response) {
    if (!response) return;
    
    if (response->challenge_id) {
        free(response->challenge_id);
        response->challenge_id = NULL;
    }
    if (response->credential_blob) {
        free(response->credential_blob);
        response->credential_blob = NULL;
    }
    if (response->encrypted_secret) {
        free(response->encrypted_secret);
        response->encrypted_secret = NULL;
    }
    if (response->hmac) {
        free(response->hmac);
        response->hmac = NULL;
    }
    if (response->enc) {
        free(response->enc);
        response->enc = NULL;
    }
    if (response->ek_hash) {
        free(response->ek_hash);
        response->ek_hash = NULL;
    }
}

