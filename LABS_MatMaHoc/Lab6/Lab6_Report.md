# Lab 6 Report: Post-Quantum Signatures & Certificates (ML-DSA, ML-KEM)

## 1. Objective & Outcomes
The objective of this lab is to transition from classical asymmetric cryptography (RSA, ECDSA) to Post-Quantum Cryptography (PQC) using NIST's standardized algorithms: **ML-DSA** (FIPS 204) for digital signatures and **ML-KEM** (FIPS 203) for Key Encapsulation Mechanisms. 

We successfully built a comprehensive C++ suite using OpenSSL 3.6.2 (which provides native PQC support via the `default` provider) to:
- Generate keys and perform Sign/Verify operations using ML-DSA-44 (Level 2) and ML-DSA-65 (Level 3).
- Perform Encapsulation/Decapsulation using ML-KEM-512 (Level 2).
- Construct a Post-Quantum Certificate Authority (PQ-CA) mini-project that issues JSON-based certificates signed with ML-DSA.
- Implement a robust benchmark testing suite evaluating latency and throughput up to 8 MiB payloads.
- Automate negative testing ensuring correct implementation of the Fujisaki-Okamoto implicit rejection mechanism.

---

## 2. Design & Security

### Parameters & Mode Choices
- **ML-DSA-44 (Security Level 2, ~128-bit classical security):** Chosen for the core CLI and PQ-CA operations due to its balance of security and performance.
- **ML-DSA-65 (Security Level 3, ~192-bit classical security):** Implemented for comparative benchmarking.
- **ML-KEM-512 (Security Level 2):** Chosen to demonstrate secure key encapsulation.

### Discussion: ML-DSA Security & Trade-offs
1. **Signature Size vs. Security:** ML-DSA produces significantly larger signatures and keys compared to ECDSA (e.g., an ML-DSA-44 public key is ~1.3KB and signature is ~2.4KB, whereas ECDSA P-256 uses a 64-byte public key and 64-byte signature). This trade-off is necessary to withstand quantum algorithms like Shor's algorithm, which easily break elliptic curves.
2. **Deterministic Signing:** ML-DSA does not rely on per-message random nonces in the same catastrophic way ECDSA does (where nonce reuse leaks the private key, requiring RFC6979). It employs robust internal deterministic constructs.
3. **Rejection Sampling:** ML-DSA relies on rejection sampling to prevent signature components from leaking information about the private key. This means signing times can have minor variances depending on how many rejections occur before a valid signature is found.

### Discussion: ML-KEM Security & Trade-offs
1. **IND-CCA Security:** ML-KEM provides Indistinguishability under Chosen Ciphertext Attack (IND-CCA2), meaning an attacker cannot deduce any information about the shared secret, even if they can decrypt arbitrarily chosen ciphertexts (excluding the target).
2. **Fujisaki–Okamoto (FO) Transform:** To achieve IND-CCA security from a weaker CPA-secure scheme, ML-KEM uses the FO transform. During decapsulation, it re-encrypts the decrypted message to verify it matches the received ciphertext. If it does not match (e.g., ciphertext was tampered), it employs **implicit rejection** by returning a pseudorandom shared secret rather than an explicit error.
3. **Ciphertext Size vs RSA:** ML-KEM ciphertexts are relatively large (~768 bytes for ML-KEM-512) compared to RSA-2048 (256 bytes) or ECDH (32 bytes). However, the performance is phenomenally faster than RSA key exchange.

---

## 3. Post-Quantum Certificates & PKI

In `cert_demo.cpp`, we implemented a minimal PQ Certificate structure in JSON, carrying a subject, a PEM-encoded ML-DSA public key, and a Base64-encoded ML-DSA signature by the "PQ-CA".

### Discussion: PKI & Migration
- **Why ML-KEM is NOT used for signing:** ML-KEM is a Key Encapsulation Mechanism. It is designed to securely establish a shared symmetric key between two parties, not to provide non-repudiation or authenticate arbitrary documents. ML-DSA is built specifically for digital signatures.
- **Hybrid Certificates (ECDSA + ML-DSA):** As a migration path, systems currently use hybrid certificates (containing both an ECDSA/RSA key and an ML-DSA key, and two signatures). This ensures that if the PQC algorithm is broken mathematically before quantum computers arrive, the classical algorithm still provides security.
- **Migration Path to PQ TLS:** TLS 1.3 is adopting PQ algorithms by adding ML-KEM to the Key Share extension for the handshake (often as a hybrid X25519 + ML-KEM share), and migrating certificate chains to ML-DSA. The main challenge is handling the large byte overhead of PQ certificates, which can cause TLS handshakes to span multiple TCP packets (fragmentation).

---

## 4. Test Methodology & Negative Tests

We automated correctness validation via `test_negative.py`.
1. **Modified Message:** Verification correctly fails (OpenSSL error 030000EA).
2. **Modified Signature:** Verification correctly fails.
3. **Modified Public Key:** Verification fails.
4. **Modified Ciphertext (ML-KEM):** Thanks to the FO Transform, decapsulation *succeeds* but produces a *completely different shared secret*. Our test script detects this divergence and marks the test as passed.
5. **Wrong Private Key (ML-KEM):** Same as above, decapsulation produces an uncorrelated pseudorandom shared secret.

---

## 5. Performance Evaluation

**Hardware & Protocol Configuration:**
- **OS:** Windows 10/11 (MSYS2 MinGW-w64 environment)
- **Compiler:** GCC (via CMake), `libcrypto-3-x64.dll` (OpenSSL 3.6.2)
- **Protocol:** `N=30` independent runs, 100 operations per block, with a 1-second warmup. Output to CSV and plotted via Seaborn (95% CI).

*(Note: Please insert the generated PNG plots from `plot_benchmark.py` here prior to submission).*

### Discussion: Performance Characteristics
1. **Hash Cost Dominance:** For large payloads (1MB, 8MB), the time taken is entirely dominated by the underlying SHAKE/SHA-3 hashing required by ML-DSA. The actual lattice math is extremely fast.
2. **Large Signature Overhead:** While operations are fast, transmitting the large ML-DSA signatures across a network induces higher latency at the network layer compared to ECDSA.
3. **Memory Usage:** Lattice algorithms require larger memory buffers for polynomial matrix arithmetic and NTT (Number Theoretic Transform) compared to elliptic curve math.
4. **Compare to ECDSA/RSA-PSS:**
   - **Keygen:** ML-DSA and ML-KEM are orders of magnitude faster than RSA KeyGen and faster than ECDSA.
   - **Verification:** ML-DSA verification is exceptionally fast (faster than ECDSA, approaching RSA public exponent speeds).
   - **Signing:** ML-DSA signing is generally faster than RSA signing but may have slight timing variances due to rejection sampling.
   - **Key Exchange:** ML-KEM provides tens of thousands of encapsulations/decapsulations per second, vastly outperforming RSA key exchange.

---

## 6. Advanced Topics (Bonus): Side-Channel Awareness

- **Timing Attack Surface & Constant-Time NTT:** ML-DSA and ML-KEM rely heavily on the Number Theoretic Transform (NTT) for polynomial multiplication. If the NTT implementation is not constant-time, an attacker could observe cache misses or CPU execution times to extract the polynomial coefficients of the private key. OpenSSL 3.6.2 integrates highly optimized, constant-time assembly for these algorithms to mitigate this.
- **Lattice Leakage Risks:** Rejection sampling in ML-DSA must be handled carefully. If the number of rejections (and thus the time taken to sign) is correlated too strongly with the secret key, it acts as a timing side-channel.
- **Failure Handling in Decapsulation:** In ML-KEM, the implicit rejection (returning a pseudorandom secret) must be done in strictly constant time. If an attacker can measure a timing difference between a valid ciphertext and an invalid one, they could bypass the FO transform (a classic CCA attack vector against KEMs).

---

## 7. Conclusion
This lab successfully demonstrates the paradigm shift required for Post-Quantum Cryptography. While the computational performance of ML-DSA and ML-KEM is outstanding (frequently beating classical RSA/ECDSA), systems engineers must adapt to their significant memory and bandwidth overheads (large keys, large signatures, large ciphertexts). Hybrid architectures will serve as the necessary bridge during this transitional decade.

---

## Appendix A — Academic Integrity & Ethics
- Work is our own; libraries utilized: OpenSSL 3.6.2, Crypto++ (for comparisons).
- Attack demonstrations are limited to offline sandbox test artifacts (tampered bytes).
- Keys and secrets included are test keys only.
- We understand the difference between vulnerability demonstration and malicious exploitation and commit to the former strictly for learning.
