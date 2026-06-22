# Lab 6: Post-Quantum Signatures & Certificates (ML-DSA, ML-KEM)

This lab implements a comprehensive suite of Post-Quantum Cryptography algorithms based on the NIST standards using OpenSSL 3.6.2 APIs.

## Requirements

- **C++ Compiler:** Supporting C++17
- **CMake:** Version 3.10+
- **OpenSSL 3.6.2:** Custom build (natively supports ML-DSA-44, ML-DSA-65, and ML-KEM-512)

## Build Instructions

1. Navigate to the `Lab6` directory.
2. Ensure you have the `libcrypto-3-x64.dll` available in your OpenSSL 3.6.2 path (`C:\msys64\home\LONG\openssl-3.6.2`).
3. Create a build directory and compile using CMake:
   ```bash
   mkdir build && cd build
   cmake -G "MinGW Makefiles" ..
   cmake --build . -j4
   ```
4. **Copy the OpenSSL 3.6.2 DLL into the `build` directory** to avoid runtime conflicts with standard OpenSSL 3.x installations:
   ```bash
   cp C:\msys64\home\LONG\openssl-3.6.2\libcrypto-3-x64.dll .
   ```

## Included Programs

### 1. `pqtool.exe`
A command-line interface for Post-Quantum cryptographic operations.

**Examples:**
```bash
# Generate ML-DSA-44 keys
./pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem

# Sign and verify
./pqtool sign --algo mldsa-44 --in msg.bin --out sig.bin --priv priv.pem
./pqtool verify --algo mldsa-44 --in msg.bin --sig sig.bin --pub pub.pem

# ML-KEM Encapsulation & Decapsulation
./pqtool keygen --algo mlkem-512 --pub kem_pub.pem --priv kem_priv.pem
./pqtool encaps --algo mlkem-512 --pub kem_pub.pem --ct ct.bin --ss ss.bin
./pqtool decaps --algo mlkem-512 --priv kem_priv.pem --ct ct.bin --ss ss_decaps.bin
```

### 2. `cert_demo.exe`
Demonstrates a Post-Quantum Certificate hierarchy. It generates a CA key pair, signs a subject's public key (formatted in JSON), and validates the integrity against tampering.

### 3. `test_negative.py`
Automated testing script orchestrating `pqtool.exe` to enforce correctness under all required negative test cases (Modified message, signature, ciphertexts, and wrong keys).

### 4. `benchmark.exe`
Measures high-resolution latencies and throughput for ML-DSA algorithms using varying payload sizes (1KiB to 8MiB) and ML-KEM encapsulation rates over 100 rounds.

## Performance Protocol
Tests are run automatically in `benchmark.exe` using `std::chrono` measuring `EVP_PKEY_keygen`, `EVP_DigestSign`/`Verify` (ML-DSA), and `EVP_PKEY_encapsulate`/`decapsulate` (ML-KEM). The output presents normalized millisecond per-operation times and MB/s throughputs directly corresponding to real-world cryptographic integration.
