# Lab 5: Negative Tests for Digital Signatures

This document outlines the test scenarios to verify the robustness of our cryptographic implementation, proving that malformed or manipulated data correctly causes the signature verification to fail.

## Test Environment Setup
We generate valid keypairs and a valid signature first:
1. `sigtool keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem`
2. `echo "This is a secret message" > msg.bin`
3. `sigtool sign --algo ecdsa-p256 --in msg.bin --out sig.bin --hash sha256 --priv priv.pem --encode raw`

---

## 1. Modified Message Test
**Scenario**: An attacker intercepts the message and alters its content while keeping the original signature attached.
**Action**:
- Edit `msg.bin` (e.g., change "secret" to "public").
- Run `sigtool verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub.pem --hash sha256`
**Expected Result**:
- Verification **FAILS**. The hash of the modified message will not match the hash decrypted/recovered from the signature.
- **UX Message**: `[FAIL] Signature Verification Failed.`

## 2. Modified Signature Test
**Scenario**: An attacker tries to forge or accidentally corrupts the signature file.
**Action**:
- Restore the original `msg.bin`.
- Modify `sig.bin` (e.g., flip one byte or append data).
- Run `sigtool verify ...`
**Expected Result**:
- Verification **FAILS**. The mathematical relation between the public key and the corrupted signature points will be invalid (for ECDSA) or padding verification will fail (for RSA-PSS).
- **UX Message**: `[FAIL] Signature Verification Failed.` (or Crypto++ throws an ASN.1 parsing error).

## 3. Wrong Public Key Test
**Scenario**: The user verifies a perfectly valid message and signature, but uses the wrong person's public key.
**Action**:
- Generate a second keypair `pub2.pem`, `priv2.pem`.
- Run `sigtool verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub2.pem --hash sha256`
**Expected Result**:
- Verification **FAILS**. The signature is mathematically bound to `priv.pem`, so it can only be verified by the corresponding `pub.pem`.
- **UX Message**: `[FAIL] Signature Verification Failed.`

## 4. Wrong Algorithm / Hash Mismatch Test
**Scenario**: Using SHA-384 to verify a signature that was generated using SHA-256.
**Action**:
- Run `sigtool verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub.pem --hash sha384`
**Expected Result**:
- Verification **FAILS**. The hash digests will differ in length and content.
- **UX Message**: `[FAIL] Signature Verification Failed.`

## 5. Unsupported Encoding / Malformed Key
**Scenario**: Providing a Base64 encoded signature but telling the tool it is raw (or vice-versa), or corrupting the PEM file structure.
**Action**:
- Run `sigtool sign ... --encode base64`
- Run `sigtool verify ... --encode raw`
**Expected Result**:
- The tool catches the formatting error without crashing and rejects the operation.
- **UX Message**: `Error: Crypto++ Error: ...` or `[FAIL] Signature Verification Failed.`
