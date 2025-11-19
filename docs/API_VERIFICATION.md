# API Verification - Client vs Backend

## Backend Server Endpoints
**Server URL:** `http://170.205.26.102:8001/`

---

## 1. `/register` Endpoint

### Backend Expects (from dev):
```python
class RegisterRequest(BaseModel):
    uuid: str          # add user mc auth
    ek_pub: str        # base64
    aik_name: str      # base64 (optional use)
    ek_cert: str       # base64 (DER format)
```

### Our Client Sends:
```json
{
  "uuid": "<generated or provided>",
  "ek_pub": "<base64 X.509 SubjectPublicKeyInfo>",
  "ek_cert": "<base64 DER> or \"\" (empty string for swtpm)",
  "aik_name": "<base64 TPM2B_NAME>"
}
```

**Status:** ✅ **MATCHES**
- All field names match exactly
- All values are base64 encoded as expected
- `ek_cert` is now always included (empty string if not available)

---

## 2. `/completeChallenge` Endpoint

### Backend Expects (from dev):
```python
class CompleteChallengeRequest(BaseModel):
    challenge_id: str
    decrypted_secret: str  # add user mc auth
```

### Our Client Sends:
```json
{
  "challenge_id": "<from register response>",
  "decrypted_secret": "<base64 decrypted secret from TPM>"
}
```

**Status:** ✅ **MATCHES**
- All field names match exactly
- `decrypted_secret` is base64 encoded as expected

---

## 3. Register Response (What We Parse)

### Expected Response Fields:
- `challenge_id` (string)
- `credential_blob` (base64 string)
- `encrypted_secret` (base64 string)
- `hmac` (base64 string)
- `enc` (base64 string)

**Status:** ✅ **READY**
- All fields are parsed correctly
- Base64 decoding handled in `tpm_activate_credential()`

---

## Summary

✅ **All API contracts match!**

The client is ready to test with the backend server at:
- `http://170.205.26.102:8001/`

### Test Command:
```bash
# Make sure swtpm is running
./scripts/start_swtpm.sh

# Run the client
./build/bin/tpm_client http://170.205.26.102:8001
```

