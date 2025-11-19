# Backend Compatibility Issue

## Problem

The backend server at `http://170.205.26.102:8001` has a validation issue with the `ek_cert` field in the `/register` endpoint.

### Current Behavior

1. **Backend Model**: Requires `ek_cert: str` (cannot be `null`)
2. **Backend Validation**: Attempts to decode base64 and parse as DER X.509 certificate
3. **Error with Empty String**: Returns `500` with `"Insufficient data - 1 bytes requested but only 0 available"`
4. **Error with Minimal DER**: Returns `500` with `"Insufficient data - 10 bytes requested but only 8 available"`

### Test Results

```bash
# Empty string - FAILS
curl -X POST http://170.205.26.102:8001/register \
  -H "Content-Type: application/json" \
  -d '{"uuid":"test","ek_pub":"...","ek_cert":"","aik_name":"..."}'
# Response: {"detail":"Insufficient data - 1 bytes requested but only 0 available"}

# Null - FAILS (validation error)
curl -X POST http://170.205.26.102:8001/register \
  -H "Content-Type: application/json" \
  -d '{"uuid":"test","ek_pub":"...","ek_cert":null,"aik_name":"..."}'
# Response: {"detail":[{"type":"string_type","loc":["body","ek_cert"],"msg":"Input should be a valid string","input":null}]}
```

## Root Cause

**swtpm (Software TPM Simulator) does not provide EK certificates.** The EK certificate is typically:
- Stored in TPM NV (Non-Volatile) storage by the manufacturer
- Not available in software simulators like swtpm
- Only available on hardware TPMs with manufacturer certificates

## Required Backend Fix

The backend should be updated to:

1. **Make `ek_cert` optional** in the Pydantic model:
   ```python
   class RegisterRequest(BaseModel):
       uuid: str
       ek_pub: str
       aik_name: str
       ek_cert: Optional[str] = None  # Make optional
   ```

2. **Skip certificate validation when empty**:
   ```python
   if req.ek_cert and len(req.ek_cert) > 0:
       # Validate and parse certificate
       ek_cert_bytes = base64.b64decode(req.ek_cert)
       # ... certificate validation ...
   else:
       # Handle missing certificate (swtpm case)
       ek_cert = None
   ```

## Current Workaround

The client currently sends a minimal DER structure (`"MgoKCAIAAAMGAA=="`) to satisfy the string requirement, but this still fails validation because it's not a valid X.509 certificate.

## Recommendation

**The backend needs to be updated** to handle empty/missing EK certificates gracefully, as this is expected behavior when using software TPM simulators like swtpm.

## Client Status

✅ **Client is working correctly** - it:
- Generates valid EK public keys (X.509 SubjectPublicKeyInfo format)
- Generates valid AIK names (base64 TPM2B_NAME)
- Sends correct JSON structure
- Handles all TPM operations correctly

The only blocker is the backend's certificate validation logic.

