# Guide 4: RSA Decryption Using Crypto++


Task 4.1 Decryption use cin to get message from screen
Task 4.2 Decryption (OAEP_SHA) use File/Source/Sink to get message (bin) from file and save output to file (bin/base64)

RSAES_OAEP_SHA_Decryptor decryptor(publicKey);
bool RSADecrypt(const std::string& SecretKeyFile,
                const std::string& inputFilePath,
                const std::string& outputBinFile)
 Task 4.3: RSA + AES for encryotion (for email example)

## Introduction

This guide demonstrates how to perform RSA decryption using the Crypto++ library. RSA decryption is the process of recovering the original plaintext from ciphertext using the private key. This guide builds on the previous guides covering ASN.1 syntax, key formats, RSA key generation, and RSA encryption.

## Prerequisites

- Crypto++ library installed (version 8.6.0 or later)
- Understanding of RSA cryptography concepts
- RSA key pair generated (see Guide 2)
- Encrypted data (see Guide 3)
- C++ development environment

## RSA Decryption Concepts

Before diving into the code, let's understand some key concepts related to RSA decryption:

1. **Private Key Requirement**: RSA decryption requires the private key, which must be kept secure and should never be shared.

2. **Padding Schemes**: The same padding scheme used for encryption must be used for decryption:
   - **PKCS#1 v1.5**: An older padding scheme, still widely used
   - **OAEP (Optimal Asymmetric Encryption Padding)**: A more secure padding scheme recommended for new applications

3. **Chinese Remainder Theorem (CRT)**: Crypto++ automatically uses CRT to speed up RSA decryption operations when the private key includes the prime factors (p and q).

4. **Hybrid Decryption**: For larger messages encrypted using hybrid encryption (RSA + symmetric encryption), the decryption process involves:
   - Decrypting the symmetric key using RSA
   - Using the recovered symmetric key to decrypt the actual message

## Basic RSA Decryption with Crypto++

Let's start with a simple example of RSA decryption using Crypto++:

```cpp
#include <iostream>
#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

int main() {
    try {
        // Load the private key for decryption
        RSA::PrivateKey privateKey;
        FileSource fs("private_key.der", true);
        privateKey.Load(fs);
        
        // Validate the key
        AutoSeededRandomPool rng;
        bool result = privateKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Private key validation failed" << std::endl;
            return 1;
        }
        
        // Load the encrypted data
        std::string ciphertext;
        FileSource fs2("rsa_encrypted.bin", true, new StringSink(ciphertext));
        
        // Decrypt using PKCS#1 v1.5 padding
        RSAES_PKCS1v15_Decryptor decryptor(privateKey);
        
        // Perform decryption
        std::string recovered;
        StringSource ss(ciphertext, true,
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(recovered)
            )
        );
        
        std::cout << "Recovered plaintext: " << recovered << std::endl;
        
    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
```

This code:
1. Loads an RSA private key from a DER file
2. Validates the key
3. Loads encrypted data from a file
4. Decrypts the data using PKCS#1 v1.5 padding
5. Outputs the recovered plaintext

## RSA Decryption with OAEP Padding

If the data was encrypted using OAEP padding, you need to use the corresponding decryption class:

```cpp
#include <cryptopp/sha.h>

// ...

// Decrypt using OAEP padding with SHA-256
RSAES_OAEP_SHA256_Decryptor decryptor(privateKey);

// Perform decryption
std::string recovered;
StringSource ss(ciphertext, true,
    new PK_DecryptorFilter(rng, decryptor,
        new StringSink(recovered)
    )
);
```

## Loading Keys from PEM Format

If you have your keys in PEM format instead of DER, you'll need to convert them before use. Here's how to load a private key from a PEM file:

```cpp
#include <fstream>
#include <cryptopp/base64.h>

RSA::PrivateKey LoadPrivateKeyFromPEM(const std::string& filename) {
    // Read the PEM file
    std::ifstream file(filename);
    std::string line, base64Data;
    bool inKey = false;
    
    while (std::getline(file, line)) {
        if (line == "-----BEGIN PRIVATE KEY-----" || line == "-----BEGIN RSA PRIVATE KEY-----") {
            inKey = true;
        } else if (line == "-----END PRIVATE KEY-----" || line == "-----END RSA PRIVATE KEY-----") {
            inKey = false;
        } else if (inKey) {
            base64Data += line;
        }
    }
    
    // Decode the Base64 data
    std::string derData;
    StringSource ss(base64Data, true,
        new Base64Decoder(
            new StringSink(derData)
        )
    );
    
    // Load the key
    RSA::PrivateKey privateKey;
    ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
    privateKey.Load(as);
    
    return privateKey;
}
```

Usage:
```cpp
RSA::PrivateKey privateKey = LoadPrivateKeyFromPEM("private_key.pem");
```

## Handling Hybrid Decryption

For messages encrypted using hybrid encryption (RSA + AES), the decryption process involves:

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

// Function for hybrid decryption (RSA + AES)
std::string HybridDecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;
    
    // Format: [encryptedKeyLength(4 bytes)][encryptedKey][IV][ciphertext]
    
    // Extract the length of the encrypted key
    if (ciphertext.size() < 4) {
        throw std::runtime_error("Invalid ciphertext format");
    }
    
    word32 keyLength = *reinterpret_cast<const word32*>(ciphertext.data());
    
    // Check if the ciphertext is long enough
    if (ciphertext.size() < 4 + keyLength + AES::BLOCKSIZE) {
        throw std::runtime_error("Invalid ciphertext format");
    }
    
    // Extract the encrypted key
    std::string encryptedKey = ciphertext.substr(4, keyLength);
    
    // Extract the IV
    byte iv[AES::BLOCKSIZE];
    memcpy(iv, ciphertext.data() + 4 + keyLength, AES::BLOCKSIZE);
    
    // Extract the AES-encrypted data
    std::string aesEncrypted = ciphertext.substr(4 + keyLength + AES::BLOCKSIZE);
    
    // Decrypt the AES key with RSA-OAEP
    RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privateKey);
    std::string recoveredKey;
    StringSource ss1(encryptedKey, true,
        new PK_DecryptorFilter(rng, rsaDecryptor,
            new StringSink(recoveredKey)
        )
    );
    
    // Decrypt the data with AES
    std::string recoveredData;
    CBC_Mode<AES>::Decryption aesDecryption(
        reinterpret_cast<const byte*>(recoveredKey.data()), 
        AES::DEFAULT_KEYLENGTH, 
        iv
    );
    
    StringSource ss2(aesEncrypted, true,
        new StreamTransformationFilter(aesDecryption,
            new StringSink(recoveredData)
        )
    );
    
    return recoveredData;
}
```

## Complete Example: RSA Decryption

Let's put everything together in a complete example that demonstrates both direct RSA decryption and hybrid decryption:

```cpp
#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

// Function to load a private key from a DER file
RSA::PrivateKey LoadPrivateKeyFromDER(const std::string& filename) {
    RSA::PrivateKey privateKey;
    FileSource fs(filename.c_str(), true);
    privateKey.Load(fs);
    return privateKey;
}

// Function to load a private key from a PEM file
RSA::PrivateKey LoadPrivateKeyFromPEM(const std::string& filename) {
    // Read the PEM file
    std::ifstream file(filename);
    std::string line, base64Data;
    bool inKey = false;
    
    while (std::getline(file, line)) {
        if (line == "-----BEGIN PRIVATE KEY-----" || line == "-----BEGIN RSA PRIVATE KEY-----") {
            inKey = true;
        } else if (line == "-----END PRIVATE KEY-----" || line == "-----END RSA PRIVATE KEY-----") {
            inKey = false;
        } else if (inKey) {
            base64Data += line;
        }
    }
    
    // Decode the Base64 data
    std::string derData;
    StringSource ss(base64Data, true,
        new Base64Decoder(
            new StringSink(derData)
        )
    );
    
    // Load the key
    RSA::PrivateKey privateKey;
    ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
    privateKey.Load(as);
    
    return privateKey;
}

// Function for direct RSA decryption with OAEP padding
std::string RSADecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;
    
    // Create a decryptor with OAEP padding
    RSAES_OAEP_SHA256_Decryptor decryptor(privateKey);
    
    // Perform decryption
    std::string recovered;
    StringSource ss(ciphertext, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(recovered)
        )
    );
    
    return recovered;
}

// Function for hybrid decryption (RSA + AES)
std::string HybridDecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;
    
    // Format: [encryptedKeyLength(4 bytes)][encryptedKey][IV][ciphertext]
    
    // Extract the length of the encrypted key
    if (ciphertext.size() < 4) {
        throw std::runtime_error("Invalid ciphertext format");
    }
    
    word32 keyLength = *reinterpret_cast<const word32*>(ciphertext.data());
    
    // Check if the ciphertext is long enough
    if (ciphertext.size() < 4 + keyLength + AES::BLOCKSIZE) {
        throw std::runtime_error("Invalid ciphertext format");
    }
    
    // Extract the encrypted key
    std::string encryptedKey = ciphertext.substr(4, keyLength);
    
    // Extract the IV
    byte iv[AES::BLOCKSIZE];
    memcpy(iv, ciphertext.data() + 4 + keyLength, AES::BLOCKSIZE);
    
    // Extract the AES-encrypted data
    std::string aesEncrypted = ciphertext.substr(4 + keyLength + AES::BLOCKSIZE);
    
    // Decrypt the AES key with RSA-OAEP
    RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privateKey);
    std::string recoveredKey;
    StringSource ss1(encryptedKey, true,
        new PK_DecryptorFilter(rng, rsaDecryptor,
            new StringSink(recoveredKey)
        )
    );
    
    // Decrypt the data with AES
    std::string recoveredData;
    CBC_Mode<AES>::Decryption aesDecryption(
        reinterpret_cast<const byte*>(recoveredKey.data()), 
        AES::DEFAULT_KEYLENGTH, 
        iv
    );
    
    StringSource ss2(aesEncrypted, true,
        new StreamTransformationFilter(aesDecryption,
            new StringSink(recoveredData)
        )
    );
    
    return recoveredData;
}

int main() {
    try {
        // Load the private key (try PEM first, fall back to DER if PEM fails)
        RSA::PrivateKey privateKey;
        try {
            privateKey = LoadPrivateKeyFromPEM("private_key.pem");
            std::cout << "Loaded private key from PEM file." << std::endl;
        } catch (const Exception&) {
            privateKey = LoadPrivateKeyFromDER("private_key.der");
            std::cout << "Loaded private key from DER file." << std::endl;
        }
        
        // Validate the key
        AutoSeededRandomPool rng;
        bool result = privateKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Private key validation failed" << std::endl;
            return 1;
        }
        
        // Load the RSA-encrypted data
        std::string rsaCiphertext;
        FileSource fs1("rsa_encrypted.bin", true, new StringSink(rsaCiphertext));
        
        // Decrypt the RSA-encrypted data
        try {
            std::string rsaRecovered = RSADecrypt(rsaCiphertext, privateKey);
            std::cout << "\nRSA decryption result: " << rsaRecovered << std::endl;
        } catch (const Exception& e) {
            std::cerr << "RSA decryption failed: " << e.what() << std::endl;
            
            // Try with PKCS#1 v1.5 padding instead
            try {
                RSAES_PKCS1v15_Decryptor pkcs1Decryptor(privateKey);
                std::string pkcs1Recovered;
                StringSource ss(rsaCiphertext, true,
                    new PK_DecryptorFilter(rng, pkcs1Decryptor,
                        new StringSink(pkcs1Recovered)
                    )
                );
                std::cout << "\nRSA decryption result (using PKCS#1 v1.5): " << pkcs1Recovered << std::endl;
            } catch (const Exception& e2) {
                std::cerr << "PKCS#1 v1.5 decryption also failed: " << e2.what() << std::endl;
            }
        }
        
        // Load the hybrid-encrypted data
        std::string hybridCiphertext;
        FileSource fs2("hybrid_encrypted.bin", true, new StringSink(hybridCiphertext));
        
        // Decrypt the hybrid-encrypted data
        try {
            std::string hybridRecovered = HybridDecrypt(hybridCiphertext, privateKey);
            std::cout << "\nHybrid decryption result: " << hybridRecovered << std::endl;
        } catch (const Exception& e) {
            std::cerr << "Hybrid decryption failed: " << e.what() << std::endl;
        } catch (const std::runtime_error& e) {
            std::cerr << "Hybrid decryption failed: " << e.what() << std::endl;
        }
        
    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
```

## RSA Decryption Schemes in Crypto++

Crypto++ provides several classes for RSA decryption with different padding schemes:

1. **RSAES_PKCS1v15_Decryptor**: Uses PKCS#1 v1.5 padding
   ```cpp
   RSAES_PKCS1v15_Decryptor decryptor(privateKey);
   ```

2. **RSAES_OAEP_SHA_Decryptor**: Uses OAEP padding with SHA-1
   ```cpp
   RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
   ```

3. **RSAES_OAEP_SHA256_Decryptor**: Uses OAEP padding with SHA-256 (more secure)
   ```cpp
   RSAES_OAEP_SHA256_Decryptor decryptor(privateKey);
   ```

## Error Handling in RSA Decryption

RSA decryption can fail for several reasons:

1. **Incorrect Private Key**: The private key doesn't correspond to the public key used for encryption.
2. **Incorrect Padding Scheme**: The padding scheme used for decryption doesn't match the one used for encryption.
3. **Corrupted Ciphertext**: The ciphertext has been modified or corrupted.
4. **Invalid Format**: For hybrid encryption, the format of the ciphertext might be incorrect.

It's important to handle these errors gracefully:

```cpp
try {
    // Try decryption with OAEP padding
    std::string recovered = RSADecrypt(ciphertext, privateKey);
    std::cout << "Decryption successful: " << recovered << std::endl;
} catch (const Exception& e) {
    std::cerr << "OAEP decryption failed: " << e.what() << std::endl;
    
    // Try with PKCS#1 v1.5 padding instead
    try {
        RSAES_PKCS1v15_Decryptor pkcs1Decryptor(privateKey);
        std::string pkcs1Recovered;
        StringSource ss(ciphertext, true,
            new PK_DecryptorFilter(rng, pkcs1Decryptor,
                new StringSink(pkcs1Recovered)
            )
        );
        std::cout << "PKCS#1 v1.5 decryption successful: " << pkcs1Recovered << std::endl;
    } catch (const Exception& e2) {
        std::cerr << "All decryption attempts failed." << std::endl;
    }
}
```

## Performance Considerations

RSA decryption is computationally expensive, especially for large key sizes. Here are some performance considerations:

1. **Chinese Remainder Theorem (CRT)**: Crypto++ automatically uses CRT to speed up RSA decryption when the private key includes the prime factors (p and q).

2. **Key Size vs. Performance**: Larger key 
(Content truncated due to size limit. Use line ranges to read in chunks)