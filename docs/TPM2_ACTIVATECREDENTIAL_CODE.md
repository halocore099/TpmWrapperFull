# TPM2_ActivateCredential Implementation Code

This document contains the relevant code for `TPM2_ActivateCredential` implementation where errors occurred during credential activation.

## Function Signature

```c
int tpm_activate_credential(const char* encrypted_secret, const char* hmac, const char* enc,
                           char** decrypted_secret)
```

## Server Response Format

The server sends:
- `credential_blob` - Custom format (not standard TPM2B_ID_OBJECT)
- `encrypted_secret` - EK-encrypted seed (may or may not have TPM2B header)
- `hmac` - HMAC value (separate field, but TPM expects it inside credential_blob)
- `enc` - Encrypted data (separate field, but TPM expects it inside credential_blob)

## Standard TPM2_ActivateCredential Protocol

The standard TPM protocol expects:
1. **TPM2B_ID_OBJECT (credential_blob)** - Contains HMAC + encrypted "inner credential"
2. **TPM2B_ENCRYPTED_SECRET** - EK-encrypted seed (OAEP-wrapped)

## Implementation Code (Standard TPM2_ActivateCredential)

Here's the correct implementation using `TPM2_ActivateCredential`:

```c
int tpm_activate_credential(const char* encrypted_secret, const char* hmac, const char* enc,
                           char** decrypted_secret) {
    if (!encrypted_secret || !hmac || !enc || !decrypted_secret) {
        log_error("tpm_activate_credential: Invalid arguments");
        return -1;
    }
    
    *decrypted_secret = NULL;
    
    size_t secret_str_len = strlen(encrypted_secret);
    size_t hmac_str_len = strlen(hmac);
    size_t enc_str_len = strlen(enc);
    
    if (secret_str_len == 0 || secret_str_len > 4096) {
        log_error("Invalid encrypted_secret length: %zu", secret_str_len);
        return -1;
    }
    
    if (hmac_str_len == 0 || hmac_str_len > 512) {
        log_error("Invalid hmac length: %zu", hmac_str_len);
        return -1;
    }
    
    if (enc_str_len == 0 || enc_str_len > 512) {
        log_error("Invalid enc length: %zu", enc_str_len);
        return -1;
    }
    
#ifdef HAVE_WOLFTPM
    int ret;
    WOLFTPM2_KEY ekKey = {0};
    WOLFTPM2_KEY aikKey = {0};
    WOLFTPM2_SESSION tpmSession = {0};
    ActivateCredential_In activCredIn = {0};
    ActivateCredential_Out activCredOut = {0};
    
    TPM2_SetActiveCtx(&g_tpm_dev.ctx);
    
    log_info("Activating credential using TPM2_ActivateCredential...");
    
    // Preserve stored AIK if we have one
    if (g_aik_stored && g_stored_aik.handle.hndl != 0) {
        log_debug("Preserving stored AIK handle 0x%08X", (unsigned int)g_stored_aik.handle.hndl);
        memcpy(&aikKey, &g_stored_aik, sizeof(WOLFTPM2_KEY));
    } else {
        log_error("AIK not available (must complete registration first)");
        return -1;
    }
    
    // Step 1: Load EK (same as registration)
    log_info("Loading manufacturer EK for credential activation...");
    
    // Try to read the persistent EK handles directly (same as registration)
    TPM_HANDLE persistent_ek_handles[] = {
        0x81010001,  // RSA EK (most common)
        0x81010002   // ECC EK
    };
    
    bool found_ek = false;
    
    // Try each persistent EK handle
    for (size_t i = 0; i < sizeof(persistent_ek_handles) / sizeof(persistent_ek_handles[0]); i++) {
        ret = wolfTPM2_ReadPublicKey(&g_tpm_dev, &ekKey, persistent_ek_handles[i]);
        if (ret == TPM_RC_SUCCESS) {
            log_info("✓ Successfully read manufacturer EK from persistent handle 0x%08X", 
                     (unsigned int)persistent_ek_handles[i]);
            found_ek = true;
            break;
        }
    }
    
    if (!found_ek) {
        log_error("Failed to load EK for activation");
        return -1;
    }
    
    // Step 2: Decode server fields
    // Decode encrypted_secret (TPM2B_ENCRYPTED_SECRET)
    size_t secret_bin_len = base64_decode_len(secret_str_len);
    uint8_t* secret_bin = (uint8_t*)malloc(secret_bin_len);
    if (!secret_bin) {
        log_error("Memory allocation failed for encrypted_secret");
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    ret = base64_decode(encrypted_secret, secret_str_len, secret_bin, secret_bin_len);
    if (ret < 0) {
        log_error("Failed to decode encrypted_secret from base64");
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    secret_bin_len = (size_t)ret;
    log_info("✓ Decoded encrypted_secret: %zu bytes", secret_bin_len);
    
    // Check if encrypted_secret has TPM2B header (2 bytes size field)
    // Server may send with or without header
    uint8_t* secret_data = secret_bin;
    size_t secret_data_len = secret_bin_len;
    
    if (secret_bin_len >= 2) {
        uint16_t size_field = (secret_bin[0] << 8) | secret_bin[1];
        if (size_field == secret_bin_len - 2) {
            // Has TPM2B header, skip it
            log_info("  encrypted_secret has TPM2B header (size: %u)", size_field);
            secret_data = secret_bin + 2;
            secret_data_len = size_field;
        } else {
            // No header, use all data
            log_info("  encrypted_secret has no TPM2B header (raw data)");
        }
    }
    
    // Decode hmac and enc to reconstruct TPM2B_ID_OBJECT
    size_t hmac_bin_len = base64_decode_len(hmac_str_len);
    uint8_t* hmac_bin = (uint8_t*)malloc(hmac_bin_len);
    if (!hmac_bin) {
        log_error("Memory allocation failed for HMAC");
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    ret = base64_decode(hmac, hmac_str_len, hmac_bin, hmac_bin_len);
    if (ret < 0 || ret != 32) {
        log_error("Failed to decode HMAC or invalid size: expected 32 bytes, got %d", ret);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    hmac_bin_len = 32;
    
    size_t enc_bin_len = base64_decode_len(enc_str_len);
    uint8_t* enc_bin = (uint8_t*)malloc(enc_bin_len);
    if (!enc_bin) {
        log_error("Memory allocation failed for enc");
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    ret = base64_decode(enc, enc_str_len, enc_bin, enc_bin_len);
    if (ret < 0) {
        log_error("Failed to decode enc from base64");
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    enc_bin_len = (size_t)ret;
    log_info("✓ Decoded enc: %zu bytes", enc_bin_len);
    
    // Step 3: Reconstruct TPM2B_ID_OBJECT from hmac and enc
    // TPM2B_ID_OBJECT structure:
    //   [size (2 bytes)] [HMAC (32 bytes)] [encrypted data (variable)]
    size_t credential_blob_size = 2 + hmac_bin_len + enc_bin_len;
    if (credential_blob_size > sizeof(activCredIn.credentialBlob.buffer)) {
        log_error("credential_blob too large: %zu bytes (max: %zu)", 
                 credential_blob_size, sizeof(activCredIn.credentialBlob.buffer));
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    // Build TPM2B_ID_OBJECT
    activCredIn.credentialBlob.size = (uint16_t)credential_blob_size;
    uint8_t* cred_ptr = activCredIn.credentialBlob.buffer;
    
    // Size field (2 bytes, big-endian)
    uint16_t cred_data_size = hmac_bin_len + enc_bin_len;
    cred_ptr[0] = (cred_data_size >> 8) & 0xFF;
    cred_ptr[1] = cred_data_size & 0xFF;
    cred_ptr += 2;
    
    // HMAC (32 bytes)
    memcpy(cred_ptr, hmac_bin, hmac_bin_len);
    cred_ptr += hmac_bin_len;
    
    // Encrypted data
    memcpy(cred_ptr, enc_bin, enc_bin_len);
    
    log_info("✓ Reconstructed TPM2B_ID_OBJECT: %u bytes", activCredIn.credentialBlob.size);
    log_info("  Structure: [size: %u] [HMAC: %zu bytes] [enc: %zu bytes]", 
             cred_data_size, hmac_bin_len, enc_bin_len);
    
    // Step 4: Build TPM2B_ENCRYPTED_SECRET
    // TPM2B_ENCRYPTED_SECRET structure:
    //   [size (2 bytes)] [encrypted secret (variable)]
    if (secret_data_len > sizeof(activCredIn.secret.buffer)) {
        log_error("encrypted_secret too large: %zu bytes (max: %zu)", 
                 secret_data_len, sizeof(activCredIn.secret.buffer));
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    activCredIn.secret.size = (uint16_t)secret_data_len;
    memcpy(activCredIn.secret.buffer, secret_data, secret_data_len);
    
    log_info("✓ Prepared TPM2B_ENCRYPTED_SECRET: %u bytes", activCredIn.secret.size);
    
    // Step 5: Set up handles
    activCredIn.activateHandle = aikKey.handle.hndl;  // AIK handle
    activCredIn.keyHandle = ekKey.handle.hndl;         // EK handle
    
    log_info("  AIK handle: 0x%08X", (unsigned int)activCredIn.activateHandle);
    log_info("  EK handle: 0x%08X", (unsigned int)activCredIn.keyHandle);
    
    // Step 6: Create EK policy session for authorization
    ekKey.handle.policyAuth = 1;
    ret = wolfTPM2_CreateAuthSession_EkPolicy(&g_tpm_dev, &tpmSession);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to create EK policy session: 0x%x", ret);
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        return -1;
    }
    
    ret = wolfTPM2_SetAuthSession(&g_tpm_dev, 1, &tpmSession, 0);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to set auth session: 0x%x", ret);
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    ret = wolfTPM2_SetAuthHandleName(&g_tpm_dev, 1, &ekKey.handle);
    if (ret != TPM_RC_SUCCESS) {
        log_error("Failed to set EK handle name: 0x%x", ret);
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    // Step 7: Call TPM2_ActivateCredential
    log_info("Calling TPM2_ActivateCredential...");
    ret = TPM2_ActivateCredential(&activCredIn, &activCredOut);
    if (ret != TPM_RC_SUCCESS) {
        const char* error_name = "UNKNOWN";
        if (ret == TPM_RC_BAD_AUTH) {
            error_name = "TPM_RC_BAD_AUTH";
        } else if (ret == TPM_RC_HANDLE) {
            error_name = "TPM_RC_HANDLE";
        } else if (ret == TPM_RC_INTEGRITY) {
            error_name = "TPM_RC_INTEGRITY";
        } else if (ret == TPM_RC_SIZE) {
            error_name = "TPM_RC_SIZE";
        }
        log_error("TPM2_ActivateCredential failed: 0x%02x (%s)", ret, error_name);
        
        if (ret == TPM_RC_BAD_AUTH) {
            log_error("");
            log_error("═══════════════════════════════════════════════════════════════");
            log_error("  TPM_RC_BAD_AUTH Error - Common Causes:");
            log_error("═══════════════════════════════════════════════════════════════");
            log_error("");
            log_error("  1. EK public key mismatch:");
            log_error("     - Server used different EK public key for TPM2_MakeCredential");
            log_error("     - Client EK doesn't match server's expected EK");
            log_error("     - Check ek_pub format (Windows vs Persistent)");
            log_error("");
            log_error("  2. AIK name mismatch:");
            log_error("     - Server used different AIK name for TPM2_MakeCredential");
            log_error("     - Client AIK doesn't match server's expected AIK");
            log_error("     - Ensure same AIK is used for registration and activation");
            log_error("");
            log_error("  3. Credential blob format error:");
            log_error("     - TPM2B_ID_OBJECT structure incorrect");
            log_error("     - HMAC or enc data corrupted");
            log_error("     - Size fields don't match actual data");
            log_error("");
            log_error("  4. EK policy authorization failed:");
            log_error("     - EK policy session not properly set up");
            log_error("     - EK policy hash doesn't match");
            log_error("");
            log_error("═══════════════════════════════════════════════════════════════");
        }
        
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    log_info("✓ TPM2_ActivateCredential successful: %u bytes", activCredOut.certInfo.size);
    
    // Step 8: Base64 encode decrypted secret
    if (activCredOut.certInfo.size == 0) {
        log_error("Decrypted secret is empty");
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    size_t decrypted_b64_len = base64_encode_len(activCredOut.certInfo.size);
    if (decrypted_b64_len == 0 || decrypted_b64_len > 8192) {
        log_error("Invalid base64 length for decrypted secret: %zu", decrypted_b64_len);
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    *decrypted_secret = (char*)malloc(decrypted_b64_len);
    if (!*decrypted_secret) {
        log_error("Memory allocation failed for decrypted_secret");
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    ret = base64_encode(activCredOut.certInfo.buffer, activCredOut.certInfo.size,
                       *decrypted_secret, decrypted_b64_len);
    if (ret < 0) {
        log_error("Failed to base64 encode decrypted secret");
        free(*decrypted_secret);
        *decrypted_secret = NULL;
        free(enc_bin);
        free(hmac_bin);
        free(secret_bin);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
        wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
        return -1;
    }
    
    // Cleanup
    free(enc_bin);
    free(hmac_bin);
    free(secret_bin);
    wolfTPM2_UnloadHandle(&g_tpm_dev, &ekKey.handle);
    wolfTPM2_UnloadHandle(&g_tpm_dev, &tpmSession.handle);
    
    log_info("✓ Credential activated successfully");
    return 0;
#else
    log_error("wolfTPM not available - rebuild with HAVE_WOLFTPM defined");
    return -1;
#endif
}
```

## Key Points

1. **TPM2B_ID_OBJECT Reconstruction**: The server sends `hmac` and `enc` separately, but TPM expects them combined in a `TPM2B_ID_OBJECT` structure with format: `[size (2)] [HMAC (32)] [enc (variable)]`

2. **TPM2B_ENCRYPTED_SECRET**: The server may send `encrypted_secret` with or without the TPM2B header. The code checks for the header and handles both cases.

3. **EK Policy Session**: The EK requires policy-based authorization. The code creates an EK policy session using `wolfTPM2_CreateAuthSession_EkPolicy`.

4. **Handle Setup**: 
   - `activateHandle` = AIK handle (the key that will receive the credential)
   - `keyHandle` = EK handle (the key used to decrypt the secret)

5. **Common Errors**:
   - `TPM_RC_BAD_AUTH`: Usually means EK/AIK mismatch or credential blob format error
   - `TPM_RC_HANDLE`: Invalid handle (EK or AIK not found)
   - `TPM_RC_INTEGRITY`: HMAC verification failed
   - `TPM_RC_SIZE`: Data size mismatch

## Differences from Custom Crypto Protocol

The standard `TPM2_ActivateCredential`:
- Uses both EK and AIK handles
- Requires TPM2B_ID_OBJECT (credential blob) with HMAC + enc combined
- Requires TPM2B_ENCRYPTED_SECRET (encrypted secret)
- Works with restricted EK keys (unlike `TPM2_RSA_Decrypt`)

The custom crypto protocol (which doesn't work with restricted EK):
- Only uses EK handle
- Directly decrypts `encrypted_secret` using `TPM2_RSA_Decrypt`
- Verifies HMAC separately
- **Fails with `TPM_RC_ATTRIBUTES` on restricted EK keys**

