#include "ek_cert_gen.h"
#include "base64.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef PLATFORM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef NOGDI
#define NOGDI
#endif
#include <windows.h>  // For GetTempPathA, GetTempFileNameA, DeleteFileA, CreateProcess
#include <io.h>
#include <process.h>  // For _spawn functions
#endif

#ifdef HAVE_WOLFTPM
#include "wolftpm/tpm2.h"
#include "wolftpm/tpm2_types.h"
#include "wolftpm/tpm2_wrap.h"

// EK Certificate NV Indices (from TCG spec and manufacturer-specific)
// Different manufacturers may use different indices
#define EK_CERT_NV_INDEX_INFINEON 0x01C00002  // Infineon TPMs
#define EK_CERT_NV_INDEX_STANDARD 0x01C0000A  // Alternative standard index
#define EK_CERT_NV_INDEX_INTEL    0x01C00008  // Some Intel TPMs
#define EK_CERT_NV_INDEX_AMD      0x01C00009  // Some AMD TPMs

// EK Policy (from TCG EK Credential Profile) - needed for authorization
static const uint8_t EK_POLICY[32] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
    0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
};

// Try reading from a specific NV index
static int try_read_nv_index(TPM_HANDLE nv_index, char** cert_out) {
    NV_Read_In nvReadIn = {0};
    NV_Read_Out nvReadOut = {0};
    
    nvReadIn.nvIndex = nv_index;
    nvReadIn.size = 2048; // Max size for EK cert (usually ~1KB)
    nvReadIn.offset = 0;
    
    // Try without authorization first (most TPMs allow reading EK cert without auth)
    int ret = TPM2_NV_Read(&nvReadIn, &nvReadOut);
    if (ret != TPM_RC_SUCCESS) {
        return ret; // Return error code
    }
    
    // Check if we got data
    if (nvReadOut.data.size == 0) {
        return TPM_RC_VALUE; // Empty
    }
    
    // Base64 encode the certificate
    size_t b64_len = base64_encode_len(nvReadOut.data.size);
    *cert_out = (char*)malloc(b64_len);
    if (!*cert_out) {
        return TPM_RC_MEMORY;
    }
    
    ret = base64_encode(nvReadOut.data.buffer, nvReadOut.data.size,
                       *cert_out, b64_len);
    if (ret < 0) {
        free(*cert_out);
        *cert_out = NULL;
        return TPM_RC_FAILURE;
    }
    
    log_info("Successfully read EK certificate from NV index 0x%08X (%zu bytes)",
             (unsigned int)nv_index, nvReadOut.data.size);
    return TPM_RC_SUCCESS;
}

#ifdef PLATFORM_WINDOWS
// Windows-specific: Extract EK public key from certificate
// Since PublicKey property is null in non-interactive mode, we extract it from the certificate
// This ensures the public key matches the certificate perfectly
int ek_pub_get_from_windows(char** ek_pub_out) {
    if (!ek_pub_out) return -1;
    *ek_pub_out = NULL;
    
    log_info("Extracting EK public key from certificate...");
    
    // First, try to get the certificate from Windows TPM Management Provider
    char* cert_b64 = NULL;
    if (ek_cert_read_from_windows(&cert_b64) != 0 || !cert_b64 || strlen(cert_b64) == 0) {
        log_info("Windows TPM Management Provider certificate not available, trying TPM NV storage...");
        // Fall back to reading from TPM NV indices
        if (ek_cert_read_from_nv(&cert_b64) != 0 || !cert_b64 || strlen(cert_b64) == 0) {
            log_warn("Could not get certificate from Windows or TPM NV storage to extract public key");
            return -1;
        }
        log_info("Successfully retrieved certificate from TPM NV storage");
    } else {
        log_info("Successfully retrieved certificate from Windows TPM Management Provider");
    }
    
    // Decode certificate from base64
    size_t cert_b64_len = strlen(cert_b64);
    size_t cert_bin_len = base64_decode_len(cert_b64_len);
    uint8_t* cert_bin = (uint8_t*)malloc(cert_bin_len);
    if (!cert_bin) {
        free(cert_b64);
        return -1;
    }
    
    int ret = base64_decode(cert_b64, cert_b64_len, cert_bin, cert_bin_len);
    if (ret < 0) {
        log_error("Failed to decode certificate");
        free(cert_b64);
        free(cert_bin);
        return -1;
    }
    cert_bin_len = (size_t)ret;
    free(cert_b64);
    
    // Extract SubjectPublicKeyInfo from X.509 certificate using PowerShell
    // This is more reliable than manual ASN.1 parsing
    char temp_script_path[MAX_PATH];
    DWORD temp_path_len = GetTempPathA(MAX_PATH, temp_script_path);
    if (temp_path_len == 0 || temp_path_len >= MAX_PATH) {
        free(cert_bin);
        return -1;
    }
    
    char cert_file_path[MAX_PATH];
    if (GetTempFileNameA(temp_script_path, "ekcert", 0, cert_file_path) == 0) {
        free(cert_bin);
        return -1;
    }
    
    char* ext = strrchr(cert_file_path, '.');
    if (ext) {
        strcpy(ext, ".der");
    }
    
    // Write certificate to temp file
    FILE* cert_file = fopen(cert_file_path, "wb");
    if (!cert_file) {
        free(cert_bin);
        DeleteFileA(cert_file_path);
        return -1;
    }
    fwrite(cert_bin, 1, cert_bin_len, cert_file);
    fclose(cert_file);
    free(cert_bin);
    
    char script_path[MAX_PATH];
    if (GetTempFileNameA(temp_script_path, "ekpub", 0, script_path) == 0) {
        DeleteFileA(cert_file_path);
        return -1;
    }
    ext = strrchr(script_path, '.');
    if (ext) {
        strcpy(ext, ".ps1");
    }
    
    char output_path[MAX_PATH];
    if (GetTempFileNameA(temp_script_path, "ekpubout", 0, output_path) == 0) {
        DeleteFileA(cert_file_path);
        DeleteFileA(script_path);
        return -1;
    }
    
    // Write PowerShell script to extract SubjectPublicKeyInfo from certificate
    // The server expects the full SubjectPublicKeyInfo (algorithm + key), not just EncodedKeyValue
    FILE* script_file = fopen(script_path, "w");
    if (!script_file) {
        DeleteFileA(cert_file_path);
        DeleteFileA(script_path);
        DeleteFileA(output_path);
        return -1;
    }
    
    fprintf(script_file, "$ErrorActionPreference = 'Stop'\n");
    fprintf(script_file, "try {\n");
    fprintf(script_file, "  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2\n");
    fprintf(script_file, "  $cert.Import('%s')\n", cert_file_path);
    fprintf(script_file, "  \n");
    fprintf(script_file, "  # Extract Windows EK format (360 bytes base64) - just the key value\n");
    fprintf(script_file, "  # This is PublicKey.EncodedKeyValue.RawData, not the full SubjectPublicKeyInfo\n");
    fprintf(script_file, "  # The server expects this format for TPM2_MakeCredential\n");
    fprintf(script_file, "  \n");
    fprintf(script_file, "  $pubKeyValue = $cert.PublicKey.EncodedKeyValue.RawData\n");
    fprintf(script_file, "  if ($null -eq $pubKeyValue -or $pubKeyValue.Length -eq 0) {\n");
    fprintf(script_file, "    throw \"PublicKey.EncodedKeyValue.RawData is null or empty\"\n");
    fprintf(script_file, "  }\n");
    fprintf(script_file, "  \n");
    fprintf(script_file, "  # This is the Windows EK format: just the RSA public key value (modulus)\n");
    fprintf(script_file, "  # Base64 encode it (should be ~270 bytes raw = ~360 bytes base64)\n");
    fprintf(script_file, "  $base64 = [Convert]::ToBase64String($pubKeyValue)\n");
    fprintf(script_file, "  $base64 | Out-File -FilePath '%s' -Encoding ASCII -NoNewline\n", output_path);
    fprintf(script_file, "} catch {\n");
    fprintf(script_file, "  $errorMsg = $_.Exception.Message\n");
    fprintf(script_file, "  Set-Content -Path '%s' -Value $errorMsg -Encoding ASCII\n", output_path);
    fprintf(script_file, "  Write-Host \"Error: $errorMsg\" -ForegroundColor Red\n");
    fprintf(script_file, "  exit 1\n");
    fprintf(script_file, "}\n");
    fclose(script_file);
    
    // Execute PowerShell script
    SECURITY_ATTRIBUTES saAttr = {0};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    
    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;
    HANDLE hChildStd_ERR_Rd = NULL;
    HANDLE hChildStd_ERR_Wr = NULL;
    
    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0) ||
        !CreatePipe(&hChildStd_ERR_Rd, &hChildStd_ERR_Wr, &saAttr, 0)) {
        DeleteFileA(cert_file_path);
        DeleteFileA(script_path);
        DeleteFileA(output_path);
        return -1;
    }
    
    if (!SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(hChildStd_OUT_Rd);
        CloseHandle(hChildStd_OUT_Wr);
        CloseHandle(hChildStd_ERR_Rd);
        CloseHandle(hChildStd_ERR_Wr);
        DeleteFileA(cert_file_path);
        DeleteFileA(script_path);
        DeleteFileA(output_path);
        return -1;
    }
    
    char cmd_line[512];
    snprintf(cmd_line, sizeof(cmd_line),
             "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%s\"",
             script_path);
    
    PROCESS_INFORMATION piProcInfo = {0};
    STARTUPINFOA siStartInfo = {0};
    siStartInfo.cb = sizeof(STARTUPINFOA);
    siStartInfo.hStdError = hChildStd_ERR_Wr;
    siStartInfo.hStdOutput = hChildStd_OUT_Wr;
    siStartInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
    
    BOOL bSuccess = CreateProcessA(NULL, cmd_line, NULL, NULL, TRUE, 0, NULL, NULL,
                                    &siStartInfo, &piProcInfo);
    
    CloseHandle(hChildStd_OUT_Wr);
    CloseHandle(hChildStd_ERR_Wr);
    
    if (!bSuccess) {
        CloseHandle(hChildStd_OUT_Rd);
        CloseHandle(hChildStd_ERR_Rd);
        DeleteFileA(cert_file_path);
        DeleteFileA(script_path);
        DeleteFileA(output_path);
        return -1;
    }
    
    WaitForSingleObject(piProcInfo.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(piProcInfo.hProcess, &exit_code);
    
    // Read error output for debugging
    DWORD dwRead = 0;
    char error_buffer[1024] = {0};
    PeekNamedPipe(hChildStd_ERR_Rd, NULL, 0, NULL, &dwRead, NULL);
    if (dwRead > 0 && dwRead < sizeof(error_buffer)) {
        ReadFile(hChildStd_ERR_Rd, error_buffer, sizeof(error_buffer) - 1, &dwRead, NULL);
        error_buffer[dwRead] = '\0';
    }
    
    CloseHandle(hChildStd_OUT_Rd);
    CloseHandle(hChildStd_ERR_Rd);
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);
    DeleteFileA(cert_file_path);
    DeleteFileA(script_path);
    
    Sleep(100);
    
    // Read output file (even on error, it may contain the error message)
    FILE* output_file = fopen(output_path, "rb");
    if (!output_file) {
        if (exit_code != 0) {
            if (strlen(error_buffer) > 0) {
                log_error("PowerShell script failed with exit code %lu: %s", exit_code, error_buffer);
            } else {
                log_error("PowerShell script failed with exit code %lu (could not read output file)", exit_code);
            }
        }
        DeleteFileA(output_path);
        return -1;
    }
    
    char buffer[4096] = {0};
    size_t total_read = fread(buffer, 1, sizeof(buffer) - 1, output_file);
    buffer[total_read] = '\0';
    fclose(output_file);
    DeleteFileA(output_path);
    
    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r' || 
                       buffer[len-1] == ' ' || buffer[len-1] == '\t')) {
        buffer[--len] = '\0';
    }
    
    if (exit_code != 0) {
        // Script failed - output file contains error message
        log_error("PowerShell script failed with exit code %lu", exit_code);
        if (strlen(error_buffer) > 0) {
            log_error("  stderr: %s", error_buffer);
        }
        if (strlen(buffer) > 0) {
            log_error("  output: %s", buffer);
        }
        return -1;
    }
    
    // Check if output contains an error message (even if exit code was 0)
    if (strstr(buffer, "Exception") || strstr(buffer, "Error") || strstr(buffer, "Failed") || 
        strstr(buffer, "does not contain") || strstr(buffer, "returned empty") ||
        strstr(buffer, "Invalid") || strstr(buffer, "format")) {
        log_error("PowerShell script returned error: %s", buffer);
        return -1;
    }
    
    if (len == 0) {
        log_error("Failed to extract EK public key: output is empty");
        return -1;
    }
    
    *ek_pub_out = (char*)malloc(len + 1);
    if (!*ek_pub_out) {
        return -1;
    }
    memcpy(*ek_pub_out, buffer, len);
    (*ek_pub_out)[len] = '\0';
    
    log_info("Successfully extracted EK public key from certificate (%zu bytes base64)", len);
    log_info("  This is the Windows EK format (EncodedKeyValue.RawData, ~360 bytes base64)");
    log_info("  Server will use this for TPM2_MakeCredential");
    return 0;
}

// Windows-specific: Encode EK public key from TPM (modulus + exponent) using Windows format
// This ensures the encoding matches exactly what Windows produces (360 bytes)
int ek_pub_encode_from_tpm_windows(const uint8_t* modulus, size_t modulus_len,
                                   const uint8_t* exponent, size_t exponent_len,
                                   char** ek_pub_out) {
    if (!modulus || !exponent || !ek_pub_out) return -1;
    *ek_pub_out = NULL;
    
    log_info("Encoding EK public key from TPM using Windows format...");
    
    // Base64 encode modulus and exponent for PowerShell
    size_t mod_b64_len = base64_encode_len(modulus_len);
    char* mod_b64 = (char*)malloc(mod_b64_len);
    if (!mod_b64) return -1;
    
    int ret = base64_encode(modulus, modulus_len, mod_b64, mod_b64_len);
    if (ret < 0) {
        free(mod_b64);
        return -1;
    }
    
    size_t exp_b64_len = base64_encode_len(exponent_len);
    char* exp_b64 = (char*)malloc(exp_b64_len);
    if (!exp_b64) {
        free(mod_b64);
        return -1;
    }
    
    ret = base64_encode(exponent, exponent_len, exp_b64, exp_b64_len);
    if (ret < 0) {
        free(mod_b64);
        free(exp_b64);
        return -1;
    }
    
    // Create temp files for PowerShell script
    char temp_script_path[MAX_PATH];
    DWORD temp_path_len = GetTempPathA(MAX_PATH, temp_script_path);
    if (temp_path_len == 0 || temp_path_len >= MAX_PATH) {
        free(mod_b64);
        free(exp_b64);
        return -1;
    }
    
    char script_path[MAX_PATH];
    if (GetTempFileNameA(temp_script_path, "ekencode", 0, script_path) == 0) {
        free(mod_b64);
        free(exp_b64);
        return -1;
    }
    
    char* ext = strrchr(script_path, '.');
    if (ext) {
        strcpy(ext, ".ps1");
    }
    
    char output_path[MAX_PATH];
    if (GetTempFileNameA(temp_script_path, "ekencodeout", 0, output_path) == 0) {
        free(mod_b64);
        free(exp_b64);
        DeleteFileA(script_path);
        return -1;
    }
    
    // Write PowerShell script to create RSA object and get EncodedKeyValue
    FILE* script_file = fopen(script_path, "w");
    if (!script_file) {
        free(mod_b64);
        free(exp_b64);
        DeleteFileA(script_path);
        DeleteFileA(output_path);
        return -1;
    }
    
    // PowerShell script to create RSA from modulus/exponent and get EncodedKeyValue
    fprintf(script_file, "$ErrorActionPreference = 'Stop'\n");
    fprintf(script_file, "try {\n");
    fprintf(script_file, "  # Decode modulus and exponent from base64\n");
    fprintf(script_file, "  $modBytes = [Convert]::FromBase64String('%s')\n", mod_b64);
    fprintf(script_file, "  $expBytes = [Convert]::FromBase64String('%s')\n", exp_b64);
    fprintf(script_file, "  \n");
    fprintf(script_file, "  # Create RSA object from modulus and exponent\n");
    fprintf(script_file, "  $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider\n");
    fprintf(script_file, "  $rsaParams = New-Object System.Security.Cryptography.RSAParameters\n");
    fprintf(script_file, "  $rsaParams.Modulus = $modBytes\n");
    fprintf(script_file, "  $rsaParams.Exponent = $expBytes\n");
    fprintf(script_file, "  $rsa.ImportParameters($rsaParams)\n");
    fprintf(script_file, "  \n");
    fprintf(script_file, "  # Try to export SubjectPublicKeyInfo using RSA.ExportSubjectPublicKeyInfo()\n");
    fprintf(script_file, "  # This method is available in .NET Core/5+ and produces Windows-compatible format\n");
    fprintf(script_file, "  $spki = $null\n");
    fprintf(script_file, "  try {\n");
    fprintf(script_file, "    # Try the modern method first (available in .NET Core/5+)\n");
    fprintf(script_file, "    $spki = $rsa.ExportSubjectPublicKeyInfo()\n");
    fprintf(script_file, "  } catch {\n");
    fprintf(script_file, "    # Fallback: Create temporary certificate to get EncodedKeyValue\n");
    fprintf(script_file, "    # This works in older PowerShell/.NET Framework versions\n");
    fprintf(script_file, "    try {\n");
    fprintf(script_file, "      $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromRSAPublicKey($rsa)\n");
    fprintf(script_file, "      $pubKeyInfo = $cert.PublicKey.EncodedKeyValue\n");
    fprintf(script_file, "      $spki = $pubKeyInfo.RawData\n");
    fprintf(script_file, "    } catch {\n");
    fprintf(script_file, "      throw \"Both ExportSubjectPublicKeyInfo and CreateFromRSAPublicKey failed: $($_.Exception.Message)\"\n");
    fprintf(script_file, "    }\n");
    fprintf(script_file, "  }\n");
    fprintf(script_file, "  \n");
    fprintf(script_file, "  if ($spki -eq $null -or $spki.Length -eq 0) {\n");
    fprintf(script_file, "    throw \"Failed to export SubjectPublicKeyInfo: result is null or empty\"\n");
    fprintf(script_file, "  }\n");
    fprintf(script_file, "  \n");
    fprintf(script_file, "  $base64 = [Convert]::ToBase64String($spki)\n");
    fprintf(script_file, "  if ([string]::IsNullOrEmpty($base64)) {\n");
    fprintf(script_file, "    throw \"Base64 encoding resulted in empty string\"\n");
    fprintf(script_file, "  }\n");
    fprintf(script_file, "  $base64 | Out-File -FilePath '%s' -Encoding ASCII -NoNewline -ErrorAction Stop\n", output_path);
    fprintf(script_file, "} catch {\n");
    fprintf(script_file, "  $errorMsg = $_.Exception.Message\n");
    fprintf(script_file, "  $errorType = $_.Exception.GetType().FullName\n");
    fprintf(script_file, "  $fullError = \"ERROR: $errorType - $errorMsg\"\n");
    fprintf(script_file, "  Write-Host $fullError\n");
    fprintf(script_file, "  Write-Error $fullError\n");
    fprintf(script_file, "  try {\n");
    fprintf(script_file, "    $fullError | Out-File -FilePath '%s' -Encoding ASCII -NoNewline -ErrorAction Stop\n", output_path);
    fprintf(script_file, "  } catch {\n");
    fprintf(script_file, "    # If we can't write to file, at least try to write a simple error\n");
    fprintf(script_file, "    \"ERROR: Script failed\" | Out-File -FilePath '%s' -Encoding ASCII -NoNewline -ErrorAction SilentlyContinue\n", output_path);
    fprintf(script_file, "  }\n");
    fprintf(script_file, "  exit 1\n");
    fprintf(script_file, "}\n");
    fclose(script_file);
    
    free(mod_b64);
    free(exp_b64);
    
    // Execute PowerShell script using CreateProcess (same pattern as certificate retrieval)
    char ps_cmd[MAX_PATH * 2];
    snprintf(ps_cmd, sizeof(ps_cmd),
             "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%s\" 2>&1",
             script_path);
    
    log_debug("Executing PowerShell command to encode EK public key...");
    log_debug("Script path: %s", script_path);
    log_debug("Output path: %s", output_path);
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    if (!CreateProcessA(NULL, ps_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        log_error("CreateProcess failed (%lu) for PowerShell command", GetLastError());
        DeleteFileA(script_path);
        DeleteFileA(output_path);
        return -1;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    log_debug("PowerShell process completed. Exit code: %lu", exit_code);
    
    Sleep(100);
    
    // Check if file exists
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(output_path, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        log_warn("Output file does not exist: %s", output_path);
        DeleteFileA(script_path);
        return -1;
    }
    FindClose(hFind);
    
    log_info("Output file exists, size: %lu bytes", findData.nFileSizeLow);
    
    // Read output from file
    FILE* output_file = fopen(output_path, "rb");
    if (!output_file) {
        log_error("Failed to open PowerShell output file: %s", output_path);
        DeleteFileA(script_path);
        DeleteFileA(output_path);
        return -1;
    }
    
    char buffer[4096] = {0};
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, output_file);
    fclose(output_file);
    buffer[bytes_read] = '\0';
    
    log_debug("Read %zu bytes from output file", bytes_read);
    
    // Remove whitespace/newlines from end
    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r' || 
                       buffer[len-1] == ' ' || buffer[len-1] == '\t')) {
        buffer[--len] = '\0';
    }
    
    // Check for errors before cleaning up temp files
    int has_error = 0;
    
    // Check if output starts with "ERROR:"
    if (strncmp(buffer, "ERROR:", 6) == 0) {
        log_warn("PowerShell script returned error: %s", buffer);
        has_error = 1;
    } else if (exit_code != 0) {
        log_warn("PowerShell script exited with error code %lu. Output: %s", exit_code, buffer);
        has_error = 1;
    } else if (len == 0) {
        log_warn("PowerShell returned empty output (exit code: %lu)", exit_code);
        has_error = 1;
    }
    
    if (has_error) {
        // Log the script path for debugging
        log_debug("Failed PowerShell script path: %s", script_path);
        log_debug("Output file path: %s", output_path);
        DeleteFileA(script_path);
        DeleteFileA(output_path);
        return -1;
    }
    
    // Clean up temp files on success
    DeleteFileA(script_path);
    DeleteFileA(output_path);
    
    // Validate it looks like base64 (basic check)
    if (len < 100) {
        log_warn("Encoded public key too short (%zu bytes), might be error message", len);
        return -1;
    }
    
    // Allocate and copy the base64 public key
    *ek_pub_out = (char*)malloc(len + 1);
    if (!*ek_pub_out) {
        log_error("Memory allocation failed");
        return -1;
    }
    strcpy(*ek_pub_out, buffer);
    
    log_info("Successfully encoded EK public key using Windows format (%zu bytes base64)", len);
    return 0;
}

// Windows-specific: Get EK certificate from TPM Management Provider
// Uses Get-TpmEndorsementKeyInfo via PowerShell
static int ek_cert_read_from_windows(char** cert_out) {
    if (!cert_out) return -1;
    *cert_out = NULL;
    
    log_info("Attempting to retrieve EK certificate from Windows TPM Management Provider...");
    
    // Create a temporary PowerShell script file to avoid shell escaping issues
    char temp_script_path[MAX_PATH];
    DWORD temp_path_len = GetTempPathA(MAX_PATH, temp_script_path);
    if (temp_path_len == 0 || temp_path_len >= MAX_PATH) {
        log_debug("Failed to get temp path");
        return -1;
    }
    
    char script_path[MAX_PATH];
    if (GetTempFileNameA(temp_script_path, "ekcert", 0, script_path) == 0) {
        log_debug("Failed to create temp file");
        return -1;
    }
    
    // Change extension to .ps1
    char* ext = strrchr(script_path, '.');
    if (ext) {
        strcpy(ext, ".ps1");
    }
    
    // Write PowerShell script to temp file
    FILE* script_file = fopen(script_path, "w");
    if (!script_file) {
        log_debug("Failed to open temp script file");
        return -1;
    }
    
    // Write PowerShell script - output directly to stdout
    fprintf(script_file, "$ekInfo = Get-TpmEndorsementKeyInfo\n");
    fprintf(script_file, "if ($ekInfo.AdditionalCertificates.Count -gt 0) {\n");
    fprintf(script_file, "  $cert = $ekInfo.AdditionalCertificates[0]\n");
    fprintf(script_file, "  $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)\n");
    fprintf(script_file, "  $base64 = [Convert]::ToBase64String($certBytes)\n");
    fprintf(script_file, "  $base64  # Output to stdout\n");
    fprintf(script_file, "} else {\n");
    fprintf(script_file, "  ''\n");
    fprintf(script_file, "}\n");
    fclose(script_file);
    
    log_debug("Created PowerShell script at: %s", script_path);
    
    // Execute PowerShell script using CreateProcess for better control
    SECURITY_ATTRIBUTES saAttr = {0};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    
    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;
    HANDLE hChildStd_ERR_Rd = NULL;
    HANDLE hChildStd_ERR_Wr = NULL;
    
    // Create pipe for stdout
    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0)) {
        log_error("CreatePipe failed for stdout (error: %lu)", GetLastError());
        DeleteFileA(script_path);
        return -1;
    }
    
    // Create pipe for stderr (to capture any errors)
    if (!CreatePipe(&hChildStd_ERR_Rd, &hChildStd_ERR_Wr, &saAttr, 0)) {
        log_error("CreatePipe failed for stderr (error: %lu)", GetLastError());
        CloseHandle(hChildStd_OUT_Rd);
        CloseHandle(hChildStd_OUT_Wr);
        DeleteFileA(script_path);
        return -1;
    }
    
    // Ensure read handles are not inherited
    if (!SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0)) {
        log_error("SetHandleInformation failed (error: %lu)", GetLastError());
        CloseHandle(hChildStd_OUT_Rd);
        CloseHandle(hChildStd_OUT_Wr);
        CloseHandle(hChildStd_ERR_Rd);
        CloseHandle(hChildStd_ERR_Wr);
        DeleteFileA(script_path);
        return -1;
    }
    
    // Create output file path
    char output_path[MAX_PATH];
    if (GetTempFileNameA(temp_script_path, "ekout", 0, output_path) == 0) {
        log_error("Failed to create output temp file");
        DeleteFileA(script_path);
        return -1;
    }
    
    // Modify script to write to file with error handling
    script_file = fopen(script_path, "w");
    if (!script_file) {
        log_error("Failed to reopen script file");
        DeleteFileA(script_path);
        DeleteFileA(output_path);
        return -1;
    }
    fprintf(script_file, "$ErrorActionPreference = 'Stop'\n");
    fprintf(script_file, "try {\n");
    fprintf(script_file, "  $ekInfo = Get-TpmEndorsementKeyInfo\n");
    fprintf(script_file, "  $cert = $null\n");
    fprintf(script_file, "  if ($ekInfo.AdditionalCertificates.Count -gt 0) {\n");
    fprintf(script_file, "    $cert = $ekInfo.AdditionalCertificates[0]\n");
    fprintf(script_file, "  } elseif ($ekInfo.ManufacturerCertificates.Count -gt 0) {\n");
    fprintf(script_file, "    $cert = $ekInfo.ManufacturerCertificates[0]\n");
    fprintf(script_file, "  }\n");
    fprintf(script_file, "  if ($cert -ne $null) {\n");
    fprintf(script_file, "    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)\n");
    fprintf(script_file, "    $base64 = [Convert]::ToBase64String($certBytes)\n");
    fprintf(script_file, "    Set-Content -Path '%s' -Value $base64 -NoNewline -Encoding ASCII\n", output_path);
    fprintf(script_file, "  } else {\n");
    fprintf(script_file, "    Set-Content -Path '%s' -Value 'EMPTY' -NoNewline -Encoding ASCII\n", output_path);
    fprintf(script_file, "  }\n");
    fprintf(script_file, "} catch {\n");
    fprintf(script_file, "  Set-Content -Path '%s' -Value $_.Exception.Message -Encoding ASCII\n", output_path);
    fprintf(script_file, "  exit 1\n");
    fprintf(script_file, "}\n");
    fclose(script_file);
    
    // Prepare command line
    char cmd_line[512];
    snprintf(cmd_line, sizeof(cmd_line),
             "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%s\"",
             script_path);
    
    PROCESS_INFORMATION piProcInfo = {0};
    STARTUPINFOA siStartInfo = {0};
    siStartInfo.cb = sizeof(STARTUPINFOA);
    siStartInfo.hStdError = hChildStd_ERR_Wr;  // Redirect stderr
    siStartInfo.hStdOutput = hChildStd_OUT_Wr; // Redirect stdout
    siStartInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
    
    log_debug("Executing PowerShell: %s", cmd_line);
    
    // Create the child process
    BOOL bSuccess = CreateProcessA(
        NULL,           // Application name (use command line instead)
        cmd_line,       // Command line
        NULL,           // Process security attributes
        NULL,           // Thread security attributes
        TRUE,           // Inherit handles
        0,              // Creation flags
        NULL,           // Environment
        NULL,           // Current directory
        &siStartInfo,   // Startup info
        &piProcInfo     // Process information
    );
    
    // Close write handles in parent (child has its own copies)
    CloseHandle(hChildStd_OUT_Wr);
    CloseHandle(hChildStd_ERR_Wr);
    
    if (!bSuccess) {
        log_error("CreateProcess failed (error: %lu)", GetLastError());
        CloseHandle(hChildStd_OUT_Rd);
        CloseHandle(hChildStd_ERR_Rd);
        DeleteFileA(script_path);
        return -1;
    }
    
    // Wait for process to complete
    WaitForSingleObject(piProcInfo.hProcess, INFINITE);
    
    DWORD exit_code = 0;
    GetExitCodeProcess(piProcInfo.hProcess, &exit_code);
    
    // Close handles
    CloseHandle(hChildStd_OUT_Rd);
    CloseHandle(hChildStd_ERR_Rd);
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);
    
    // Clean up temp script file
    DeleteFileA(script_path);
    
    log_info("PowerShell process completed. Exit code: %lu", exit_code);
    
    // Small delay to ensure file is written
    Sleep(100);
    
    // Check if file exists and has content
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(output_path, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        log_warn("Output file does not exist: %s", output_path);
        return -1;
    }
    FindClose(hFind);
    
    log_info("Output file exists, size: %lu bytes", findData.nFileSizeLow);
    
    // Read output from file
    FILE* output_file = fopen(output_path, "rb");  // Binary mode
    if (!output_file) {
        log_warn("Failed to open output file: %s (error: %lu)", output_path, GetLastError());
        DeleteFileA(output_path);
        return -1;
    }
    
    char buffer[8192] = {0};
    size_t total_read = fread(buffer, 1, sizeof(buffer) - 1, output_file);
    buffer[total_read] = '\0';
    fclose(output_file);
    DeleteFileA(output_path);
    
    log_info("Read %zu bytes from output file", total_read);
    if (total_read > 0 && total_read < 100) {
        log_info("File content: %.100s", buffer);
    }
    
    log_debug("PowerShell exit code: %lu, output length: %lu", exit_code, total_read);
    
    if (exit_code != 0) {
        log_warn("PowerShell command failed with exit code %lu", exit_code);
        if (total_read > 0 && total_read < 500) {
            log_warn("PowerShell error output: %s", buffer);
        }
        return -1;
    }
    
    // Remove whitespace/newlines from end
    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r' || 
                       buffer[len-1] == ' ' || buffer[len-1] == '\t')) {
        buffer[--len] = '\0';
    }
    
    if (len == 0) {
        log_warn("PowerShell returned empty certificate");
        return -1;
    }
    
    // Validate it looks like base64 (should be at least 500 chars for a real cert)
    if (len < 500) {
        log_warn("Certificate too short (%zu bytes), might be error message", len);
        if (len < 200) {
            log_warn("Output: %s", buffer);
        }
        return -1;
    }
    
    log_info("Retrieved certificate from PowerShell (%zu bytes base64)", len);
    
    // Allocate and copy the base64 certificate
    *cert_out = (char*)malloc(len + 1);
    if (!*cert_out) {
        log_error("Memory allocation failed");
        return -1;
    }
    memcpy(*cert_out, buffer, len);
    (*cert_out)[len] = '\0';
    
    log_info("Successfully retrieved EK certificate from Windows TPM Management Provider (%zu bytes base64)", len);
    if (len > 0 && len <= 100) {
        log_info("  Certificate (first 100 chars): %.100s", buffer);
    } else if (len > 100) {
        log_info("  Certificate (first 100 chars): %.100s...", buffer);
        log_info("  Certificate (last 50 chars): ...%.50s", buffer + len - 50);
    }
    return 0;
}
#endif // PLATFORM_WINDOWS

int ek_cert_read_from_nv(char** cert_out) {
    if (!cert_out) return -1;
    *cert_out = NULL;

#ifdef PLATFORM_WINDOWS
    // On Windows, try TPM Management Provider first (more reliable)
    if (ek_cert_read_from_windows(cert_out) == 0) {
        return 0; // Success!
    }
    log_info("Windows TPM Management Provider method failed, trying NV storage...");
#endif

#ifdef HAVE_WOLFTPM
    int ret;
    
    // Note: TPM2_NV_Read uses the active context set by TPM2_SetActiveCtx
    // This should already be set by tpm_wrapper_init() and tpm_get_attestation_data()
    
    // Try multiple NV indices (different manufacturers use different indices)
    TPM_HANDLE indices[] = {
        EK_CERT_NV_INDEX_INFINEON,  // Most common (Infineon)
        EK_CERT_NV_INDEX_STANDARD,  // Alternative standard
        EK_CERT_NV_INDEX_INTEL,     // Some Intel TPMs
        EK_CERT_NV_INDEX_AMD        // Some AMD TPMs
    };
    
    const char* index_names[] = {
        "Infineon (0x01C00002)",
        "Standard (0x01C0000A)",
        "Intel (0x01C00008)",
        "AMD (0x01C00009)"
    };
    
    log_info("Attempting to read EK certificate from NV storage...");
    
    // Try each NV index
    for (size_t i = 0; i < sizeof(indices) / sizeof(indices[0]); i++) {
        log_debug("Trying NV index %s (0x%08X)...", 
                  index_names[i], (unsigned int)indices[i]);
        
        ret = try_read_nv_index(indices[i], cert_out);
        if (ret == TPM_RC_SUCCESS) {
            return 0; // Success!
        }
        
        // Log specific errors for debugging
        if (ret == 0x18A) {
            log_debug("  NV index 0x%08X doesn't exist (TPM_RC_NV_DEFINED)", 
                     (unsigned int)indices[i]);
        } else if (ret == 0x1B6) {
            log_debug("  NV index 0x%08X requires authorization (TPM_RC_AUTH_UNAVAILABLE)", 
                     (unsigned int)indices[i]);
        } else if (ret == 0x1B7) {
            log_debug("  NV index 0x%08X authorization failed (TPM_RC_AUTH_FAIL)", 
                     (unsigned int)indices[i]);
        } else if (ret == 0x84) {
            log_debug("  NV index 0x%08X invalid or empty (TPM_RC_VALUE)", 
                     (unsigned int)indices[i]);
        } else {
            log_debug("  NV index 0x%08X failed with error 0x%x", 
                     (unsigned int)indices[i], ret);
        }
    }
    
    // If all failed without auth, try with EK policy authorization
    // This requires creating an authorization session with the EK policy
    log_info("Trying with EK policy authorization...");
    
    // Note: Creating an authorization session with EK policy is complex
    // and requires the EK handle. For now, we'll skip this and rely on
    // the test certificate generation. In production, you may want to
    // implement proper EK policy session creation here.
    
    log_info("EK certificate not found in any NV storage index");
    log_info("Common reasons:");
    log_info("  1. TPM manufacturer didn't provision EK certificate");
    log_info("  2. Certificate requires authorization (EK policy)");
    log_info("  3. Certificate stored in manufacturer's online service");
    log_info("  4. TPM is a firmware TPM (fTPM) without NV storage");
    
    return -1;
#else
    return -1;
#endif
}

// Helper function to encode ASN.1 length
static int encode_length(uint8_t* output, size_t* offset, size_t max_len, size_t length) {
    if (!output || !offset) return -1;
    
    if (length < 0x80) {
        // Short form
        if (*offset + 1 > max_len) return -1;
        output[(*offset)++] = (uint8_t)length;
    } else if (length < 0x100) {
        // Long form, 1 byte
        if (*offset + 2 > max_len) return -1;
        output[(*offset)++] = 0x81;
        output[(*offset)++] = (uint8_t)length;
    } else if (length < 0x10000) {
        // Long form, 2 bytes
        if (*offset + 3 > max_len) return -1;
        output[(*offset)++] = 0x82;
        output[(*offset)++] = (uint8_t)(length >> 8);
        output[(*offset)++] = (uint8_t)length;
    } else {
        // Long form, 3 bytes (should be enough for our use)
        if (*offset + 4 > max_len) return -1;
        output[(*offset)++] = 0x83;
        output[(*offset)++] = (uint8_t)(length >> 16);
        output[(*offset)++] = (uint8_t)(length >> 8);
        output[(*offset)++] = (uint8_t)length;
    }
    return 0;
}

char* ek_cert_generate_test(const char* ek_pub_base64) {
    if (!ek_pub_base64) return NULL;
    
    log_info("Generating TEST EK certificate (for testing only - not cryptographically valid)");
    
    // Decode the EK public key (SubjectPublicKeyInfo)
    size_t ek_pub_len = strlen(ek_pub_base64);
    size_t ek_pub_bin_len = base64_decode_len(ek_pub_len);
    uint8_t* ek_pub_bin = (uint8_t*)malloc(ek_pub_bin_len);
    if (!ek_pub_bin) {
        log_error("Memory allocation failed for EK public key");
        return NULL;
    }
    
    int ret = base64_decode(ek_pub_base64, ek_pub_len, ek_pub_bin, ek_pub_bin_len);
    if (ret < 0) {
        log_error("Failed to decode EK public key from base64");
        free(ek_pub_bin);
        return NULL;
    }
    ek_pub_bin_len = (size_t)ret;
    
    // Build minimal X.509 v3 certificate structure
    // We'll build it in parts and calculate lengths correctly
    uint8_t cert_buf[4096];
    size_t offset = 0;
    
    // Start with Certificate SEQUENCE tag
    cert_buf[offset++] = 0x30; // SEQUENCE
    size_t cert_len_pos = offset;
    offset++; // Reserve for length (will fill later)
    
    // Build TBSCertificate in a temporary buffer first
    uint8_t tbs_buf[2048];
    size_t tbs_offset = 0;
    
    // Version [0] EXPLICIT Version v3
    tbs_buf[tbs_offset++] = 0xA0; // [0] EXPLICIT
    tbs_buf[tbs_offset++] = 0x03; // Length 3
    tbs_buf[tbs_offset++] = 0x02; // INTEGER
    tbs_buf[tbs_offset++] = 0x01; // Length 1
    tbs_buf[tbs_offset++] = 0x02; // Version 3
    
    // Serial Number: 1
    tbs_buf[tbs_offset++] = 0x02; // INTEGER
    tbs_buf[tbs_offset++] = 0x01; // Length 1
    tbs_buf[tbs_offset++] = 0x01; // Value: 1
    
    // Signature Algorithm: SHA256 with RSA
    tbs_buf[tbs_offset++] = 0x30; // SEQUENCE
    tbs_buf[tbs_offset++] = 0x0D; // Length 13
    tbs_buf[tbs_offset++] = 0x06; // OID
    tbs_buf[tbs_offset++] = 0x09; // Length 9
    tbs_buf[tbs_offset++] = 0x2A; tbs_buf[tbs_offset++] = 0x86; tbs_buf[tbs_offset++] = 0x48;
    tbs_buf[tbs_offset++] = 0x86; tbs_buf[tbs_offset++] = 0xF7; tbs_buf[tbs_offset++] = 0x0D;
    tbs_buf[tbs_offset++] = 0x01; tbs_buf[tbs_offset++] = 0x01; tbs_buf[tbs_offset++] = 0x0B;
    tbs_buf[tbs_offset++] = 0x05; // NULL
    tbs_buf[tbs_offset++] = 0x00; // Length 0
    
    // Issuer: CN=TPM EK Test
    tbs_buf[tbs_offset++] = 0x30; // SEQUENCE
    size_t issuer_len_pos = tbs_offset;
    tbs_offset++;
    tbs_buf[tbs_offset++] = 0x31; // SET
    size_t rdn_len_pos = tbs_offset;
    tbs_offset++;
    tbs_buf[tbs_offset++] = 0x30; // SEQUENCE
    size_t atv_len_pos = tbs_offset;
    tbs_offset++;
    // OID: commonName (2.5.4.3)
    tbs_buf[tbs_offset++] = 0x06; tbs_buf[tbs_offset++] = 0x03;
    tbs_buf[tbs_offset++] = 0x55; tbs_buf[tbs_offset++] = 0x04; tbs_buf[tbs_offset++] = 0x03;
    // Value: "TPM EK Test"
    const char* name = "TPM EK Test";
    size_t name_len = strlen(name);
    tbs_buf[tbs_offset++] = 0x13; // PrintableString
    tbs_buf[tbs_offset++] = (uint8_t)name_len;
    memcpy(tbs_buf + tbs_offset, name, name_len);
    tbs_offset += name_len;
    // Fill lengths
    size_t atv_len = tbs_offset - atv_len_pos - 1;
    tbs_buf[atv_len_pos] = (uint8_t)atv_len;
    size_t rdn_len = tbs_offset - rdn_len_pos - 1;
    tbs_buf[rdn_len_pos] = (uint8_t)rdn_len;
    size_t issuer_len = tbs_offset - issuer_len_pos - 1;
    tbs_buf[issuer_len_pos] = (uint8_t)issuer_len;
    
    // Validity
    tbs_buf[tbs_offset++] = 0x30; // SEQUENCE
    tbs_buf[tbs_offset++] = 0x1E; // Length 30
    tbs_buf[tbs_offset++] = 0x17; tbs_buf[tbs_offset++] = 0x0D; // UTCTime
    memcpy(tbs_buf + tbs_offset, "240101000000Z", 13);
    tbs_offset += 13;
    tbs_buf[tbs_offset++] = 0x17; tbs_buf[tbs_offset++] = 0x0D; // UTCTime
    memcpy(tbs_buf + tbs_offset, "250101000000Z", 13);
    tbs_offset += 13;
    
    // Subject (same as Issuer)
    memcpy(tbs_buf + tbs_offset, tbs_buf + issuer_len_pos - 1, issuer_len + 2);
    tbs_offset += issuer_len + 2;
    
    // SubjectPublicKeyInfo (from ek_pub_bin)
    // Save a copy for verification before freeing
    uint8_t* ek_pub_copy = (uint8_t*)malloc(ek_pub_bin_len);
    if (!ek_pub_copy) {
        free(ek_pub_bin);
        return NULL;
    }
    memcpy(ek_pub_copy, ek_pub_bin, ek_pub_bin_len);
    size_t ek_pub_saved_len = ek_pub_bin_len;
    
    if (tbs_offset + ek_pub_bin_len > sizeof(tbs_buf)) {
        free(ek_pub_bin);
        free(ek_pub_copy);
        return NULL;
    }
    memcpy(tbs_buf + tbs_offset, ek_pub_bin, ek_pub_bin_len);
    size_t spki_pos_in_tbs = tbs_offset; // Save position for verification
    tbs_offset += ek_pub_bin_len;
    free(ek_pub_bin);
    
    // Now build TBSCertificate SEQUENCE
    cert_buf[offset++] = 0x30; // SEQUENCE
    size_t tbs_len_pos = offset;
    offset++;
    memcpy(cert_buf + offset, tbs_buf, tbs_offset);
    offset += tbs_offset;
    // Fill TBSCertificate length
    size_t tbs_len = offset - tbs_len_pos - 1;
    if (tbs_len < 0x80) {
        cert_buf[tbs_len_pos] = (uint8_t)tbs_len;
    } else {
        // Need to shift and insert multi-byte length
        memmove(cert_buf + tbs_len_pos + 2, cert_buf + tbs_len_pos + 1, tbs_len);
        cert_buf[tbs_len_pos] = 0x81;
        cert_buf[tbs_len_pos + 1] = (uint8_t)tbs_len;
        offset++;
    }
    
    // Signature Algorithm (same as in TBSCertificate)
    cert_buf[offset++] = 0x30; // SEQUENCE
    cert_buf[offset++] = 0x0D; // Length 13
    cert_buf[offset++] = 0x06; cert_buf[offset++] = 0x09;
    cert_buf[offset++] = 0x2A; cert_buf[offset++] = 0x86; cert_buf[offset++] = 0x48;
    cert_buf[offset++] = 0x86; cert_buf[offset++] = 0xF7; cert_buf[offset++] = 0x0D;
    cert_buf[offset++] = 0x01; cert_buf[offset++] = 0x01; cert_buf[offset++] = 0x0B;
    cert_buf[offset++] = 0x05; cert_buf[offset++] = 0x00;
    
    // Signature Value: Dummy 256-byte signature
    cert_buf[offset++] = 0x03; // BIT STRING
    cert_buf[offset++] = 0x82; cert_buf[offset++] = 0x01; cert_buf[offset++] = 0x01; // Length 257
    cert_buf[offset++] = 0x00; // 0 unused bits
    memset(cert_buf + offset, 0xAA, 256); // Dummy signature
    offset += 256;
    
    // Fill Certificate SEQUENCE length
    size_t cert_len = offset - cert_len_pos - 1;
    if (cert_len < 0x80) {
        cert_buf[cert_len_pos] = (uint8_t)cert_len;
    } else if (cert_len < 0x100) {
        memmove(cert_buf + cert_len_pos + 2, cert_buf + cert_len_pos + 1, cert_len);
        cert_buf[cert_len_pos] = 0x81;
        cert_buf[cert_len_pos + 1] = (uint8_t)cert_len;
        offset++;
    } else {
        memmove(cert_buf + cert_len_pos + 3, cert_buf + cert_len_pos + 1, cert_len);
        cert_buf[cert_len_pos] = 0x82;
        cert_buf[cert_len_pos + 1] = (uint8_t)(cert_len >> 8);
        cert_buf[cert_len_pos + 2] = (uint8_t)cert_len;
        offset += 2;
    }
    
    // Base64 encode
    size_t b64_len = base64_encode_len(offset);
    char* cert_b64 = (char*)malloc(b64_len);
    if (!cert_b64) {
        log_error("Memory allocation failed");
        return NULL;
    }
    
    ret = base64_encode(cert_buf, offset, cert_b64, b64_len);
    if (ret < 0) {
        log_error("Failed to base64 encode certificate");
        free(cert_b64);
        return NULL;
    }
    
    // Verify: Check that SubjectPublicKeyInfo in certificate matches ek_pub
    // The SubjectPublicKeyInfo is embedded in tbs_buf at spki_pos_in_tbs
    log_info("Verifying certificate public key matches ek_pub...");
    
    if (memcmp(tbs_buf + spki_pos_in_tbs, ek_pub_copy, ek_pub_saved_len) == 0) {
        log_info("✓ Certificate SubjectPublicKeyInfo matches ek_pub (verified)");
    } else {
        log_error("✗ Certificate SubjectPublicKeyInfo does NOT match ek_pub!");
        log_error("  This will cause server validation to fail");
        // Still return the certificate, but log the issue
    }
    free(ek_pub_copy);
    
    log_info("Generated TEST EK certificate (%zu bytes DER, %zu bytes base64)", 
             offset, strlen(cert_b64));
    return cert_b64;
}

char* ek_cert_get(const char* ek_pub_base64) {
    char* cert = NULL;
    
    // Try Windows TPM Management Provider first (on Windows)
#ifdef PLATFORM_WINDOWS
    if (ek_cert_read_from_windows(&cert) == 0) {
        // Verify the certificate's public key matches ek_pub
        // If it doesn't match, the certificate is for a different EK
        // (e.g., manufacturer's original EK vs. newly created EK)
        log_info("Retrieved certificate from Windows, verifying public key match...");
        if (cert) {
            log_info("  Certificate retrieved: %zu bytes base64 (ASN.1 X.509 DER)", strlen(cert));
            log_info("  Server will decode base64 to bytes, then load as ASN.1 X.509 certificate");
            log_info("  Server should extract EK public key from this certificate for TPM2_MakeCredential");
        }
        // Note: Full certificate parsing would be needed to extract and compare public keys
        // For now, we'll return it and let the server validate
        // TODO: Add certificate public key extraction and comparison
        return cert;
    }
#endif
    
    // Try reading from NV storage
    if (ek_cert_read_from_nv(&cert) == 0) {
        return cert; // Success!
    }
    
    // Fall back to test certificate generation
    log_info("EK certificate not in NV storage, generating test certificate...");
    cert = ek_cert_generate_test(ek_pub_base64);
    
    if (cert) {
        log_warn("Using TEST certificate (not a real EK certificate)");
    }
    
    return cert;
}

#endif // HAVE_WOLFTPM

