# Guide 3: RSA Encryption Using Crypto++
Task 3.1 Encryption use cin to get message from screen
Task 3.2 Encryption (OAEP_SHA) use File/Source/Sink to get message (bin) from file and save output to file (bin/base64)

## Introduction

This guide demonstrates how to perform RSA encryption using the Crypto++ library. RSA encryption is an asymmetric cryptographic algorithm that uses a public key for encryption and a private key for decryption. This guide builds on the previous guides covering ASN.1 syntax, key formats, and RSA key generation.

## Prerequisites

- Crypto++ library installed (version 8.6.0 or later)
- Understanding of RSA cryptography concepts
- RSA key pair generated (see Guide 2)
- C++ development environment

## RSA Encryption Concepts

Before diving into the code, let's understand some key concepts related to RSA encryption:

1. **Asymmetric Encryption**: RSA uses different keys for encryption (public key) and decryption (private key).

2. **Message Size Limitations**: RSA can only encrypt data up to a certain size, which is slightly less than the key size in bytes. For example, a 3072-bit key can encrypt up to approximately 384 bytes.

3. **Padding Schemes**: Raw RSA encryption is vulnerable to various attacks, so padding schemes are used to enhance security:
   - **PKCS#1 v1.5**: An older padding scheme, still widely used but has known vulnerabilities
   - **OAEP (Optimal Asymmetric Encryption Padding)**: A more secure padding scheme recommended for new applications

4. **Hybrid Encryption**: For larger messages, RSA is typically used to encrypt a random symmetric key, which is then used to encrypt the actual message using a symmetric algorithm like AES.

## Basic RSA Encryption with Crypto++

Let's start with a simple example of RSA encryption using Crypto++:

```cpp
#include <iostream>
#include <string>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

int main() {
    try {
        // Load the public key for encryption
        RSA::PublicKey publicKey;
        FileSource fs("public_key.der", true);
        publicKey.Load(fs);
        
        // Validate the key
        AutoSeededRandomPool rng;
        bool result = publicKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Public key validation failed" << std::endl;
            return 1;
        }
        
        // Message to encrypt
        std::string plaintext = "RSA encryption test with Crypto++";
        std::cout << "Plaintext: " << plaintext << std::endl;
        
        // Encrypt using PKCS#1 v1.5 padding
        RSAES_PKCS1v15_Encryptor encryptor(publicKey);
        
        // Check if the message fits within the maximum size
        size_t maxPlaintextLength = encryptor.FixedMaxPlaintextLength();
        if (plaintext.length() > maxPlaintextLength) {
            std::cerr << "Message too long for RSA encryption. Maximum length: " 
                      << maxPlaintextLength << " bytes." << std::endl;
            return 1;
        }
        
        // Perform encryption
        std::string ciphertext;
        StringSource ss(plaintext, true,
            new PK_EncryptorFilter(rng, encryptor,
                new StringSink(ciphertext)
            )
        );
        
        // Output the encrypted data in Base64 format for readability
        std::string encoded;
        StringSource ss2(ciphertext, true,
            new Base64Encoder(
                new StringSink(encoded)
            )
        );
        
        std::cout << "Ciphertext (Base64): " << encoded << std::endl;
        
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
1. Loads an RSA public key from a DER file
2. Validates the key
3. Encrypts a message using PKCS#1 v1.5 padding
4. Outputs the encrypted data in Base64 format

## RSA Encryption with OAEP Padding

OAEP padding is more secure than PKCS#1 v1.5 and is recommended for new applications. Here's how to use it:

```cpp
#include <cryptopp/sha.h>

// ...

// Encrypt using OAEP padding with SHA-256
RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

// Check if the message fits within the maximum size
size_t maxPlaintextLength = encryptor.FixedMaxPlaintextLength();
if (plaintext.length() > maxPlaintextLength) {
    std::cerr << "Message too long for RSA encryption. Maximum length: " 
              << maxPlaintextLength << " bytes." << std::endl;
    return 1;
}

// Perform encryption
std::string ciphertext;
StringSource ss(plaintext, true,
    new PK_EncryptorFilter(rng, encryptor,
        new StringSink(ciphertext)
    )
);
```

Note that OAEP reduces the maximum message size slightly compared to PKCS#1 v1.5 due to the additional padding.

## Loading Keys from PEM Format

If you have your keys in PEM format instead of DER, you'll need to convert them before use. Here's how to load a public key from a PEM file:

```cpp
#include <fstream>
#include <cryptopp/base64.h>

RSA::PublicKey LoadPublicKeyFromPEM(const std::string& filename) {
    // Read the PEM file
    std::ifstream file(filename);
    std::string line, base64Data;
    bool inKey = false;
    
    while (std::getline(file, line)) {
        if (line == "-----BEGIN PUBLIC KEY-----") {
            inKey = true;
        } else if (line == "-----END PUBLIC KEY-----") {
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
    RSA::PublicKey publicKey;
    ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
    publicKey.Load(as);
    
    return publicKey;
}
```

Usage:
```cpp
RSA::PublicKey publicKey = LoadPublicKeyFromPEM("public_key.pem");
```

## Handling Larger Messages with Hybrid Encryption

As mentioned earlier, RSA can only encrypt small messages. For larger data, we use hybrid encryption:

1. Generate a random symmetric key (e.g., for AES)
2. Encrypt the actual message with the symmetric key
3. Encrypt the symmetric key with RSA
4. Combine the encrypted symmetric key and the encrypted message

Here's an example using AES-256 in CBC mode:

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

// Function for hybrid encryption
std::string HybridEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey) {
    AutoSeededRandomPool rng;
    
    // Generate a random AES key
    byte aesKey[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(aesKey, sizeof(aesKey));
    rng.GenerateBlock(iv, sizeof(iv));
    
    // Encrypt the plaintext with AES
    std::string ciphertext;
    CBC_Mode<AES>::Encryption aesEncryption(aesKey, sizeof(aesKey), iv);
    StringSource ss1(plaintext, true, 
        new StreamTransformationFilter(aesEncryption,
            new StringSink(ciphertext)
        )
    );
    
    // Encrypt the AES key with RSA-OAEP
    RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);
    std::string encryptedKey;
    StringSource ss2(aesKey, sizeof(aesKey), true,
        new PK_EncryptorFilter(rng, rsaEncryptor,
            new StringSink(encryptedKey)
        )
    );
    
    // Combine the encrypted key, IV, and ciphertext
    // Format: [encryptedKeyLength(4 bytes)][encryptedKey][IV][ciphertext]
    std::string result;
    
    // Add the length of the encrypted key as a 4-byte integer
    word32 keyLength = static_cast<word32>(encryptedKey.size());
    result.append(reinterpret_cast<const char*>(&keyLength), 4);
    
    // Add the encrypted key, IV, and ciphertext
    result += encryptedKey;
    result.append(reinterpret_cast<const char*>(iv), sizeof(iv));
    result += ciphertext;
    
    return result;
}
```

## Complete Example: RSA Encryption

Let's put everything together in a complete example that demonstrates both direct RSA encryption and hybrid encryption:

```cpp
#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

// Function to load a public key from a DER file
RSA::PublicKey LoadPublicKeyFromDER(const std::string& filename) {
    RSA::PublicKey publicKey;
    FileSource fs(filename.c_str(), true);
    publicKey.Load(fs);
    return publicKey;
}

// Function to load a public key from a PEM file
RSA::PublicKey LoadPublicKeyFromPEM(const std::string& filename) {
    // Read the PEM file
    std::ifstream file(filename);
    std::string line, base64Data;
    bool inKey = false;
    
    while (std::getline(file, line)) {
        if (line == "-----BEGIN PUBLIC KEY-----") {
            inKey = true;
        } else if (line == "-----END PUBLIC KEY-----") {
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
    RSA::PublicKey publicKey;
    ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
    publicKey.Load(as);
    
    return publicKey;
}

// Function for direct RSA encryption with OAEP padding
std::string RSAEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey) {
    AutoSeededRandomPool rng;
    
    // Create an encryptor with OAEP padding
    RSAES_OAEP_SHA256_Encryptor encryptor(publicKey);
    
    // Check if the message fits within the maximum size
    size_t maxPlaintextLength = encryptor.FixedMaxPlaintextLength();
    if (plaintext.length() > maxPlaintextLength) {
        throw std::runtime_error("Message too long for RSA encryption. Maximum length: " + 
                                 std::to_string(maxPlaintextLength) + " bytes.");
    }
    
    // Perform encryption
    std::string ciphertext;
    StringSource ss(plaintext, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext)
        )
    );
    
    return ciphertext;
}

// Function for hybrid encryption (RSA + AES)
std::string HybridEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey) {
    AutoSeededRandomPool rng;
    
    // Generate a random AES key
    byte aesKey[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(aesKey, sizeof(aesKey));
    rng.GenerateBlock(iv, sizeof(iv));
    
    // Encrypt the plaintext with AES
    std::string ciphertext;
    CBC_Mode<AES>::Encryption aesEncryption(aesKey, sizeof(aesKey), iv);
    StringSource ss1(plaintext, true, 
        new StreamTransformationFilter(aesEncryption,
            new StringSink(ciphertext)
        )
    );
    
    // Encrypt the AES key with RSA-OAEP
    RSAES_OAEP_SHA256_Encryptor rsaEncryptor(publicKey);
    std::string encryptedKey;
    StringSource ss2(aesKey, sizeof(aesKey), true,
        new PK_EncryptorFilter(rng, rsaEncryptor,
            new StringSink(encryptedKey)
        )
    );
    
    // Combine the encrypted key, IV, and ciphertext
    // Format: [encryptedKeyLength(4 bytes)][encryptedKey][IV][ciphertext]
    std::string result;
    
    // Add the length of the encrypted key as a 4-byte integer
    word32 keyLength = static_cast<word32>(encryptedKey.size());
    result.append(reinterpret_cast<const char*>(&keyLength), 4);
    
    // Add the encrypted key, IV, and ciphertext
    result += encryptedKey;
    result.append(reinterpret_cast<const char*>(iv), sizeof(iv));
    result += ciphertext;
    
    return result;
}

// Function to encode binary data to Base64
std::string Base64Encode(const std::string& data) {
    std::string encoded;
    StringSource ss(data, true,
        new Base64Encoder(
            new StringSink(encoded)
        )
    );
    return encoded;
}

int main() {
    try {
        // Load the public key (try PEM first, fall back to DER if PEM fails)
        RSA::PublicKey publicKey;
        try {
            publicKey = LoadPublicKeyFromPEM("public_key.pem");
            std::cout << "Loaded public key from PEM file." << std::endl;
        } catch (const Exception&) {
            publicKey = LoadPublicKeyFromDER("public_key.der");
            std::cout << "Loaded public key from DER file." << std::endl;
        }
        
        // Validate the key
        AutoSeededRandomPool rng;
        bool result = publicKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Public key validation failed" << std::endl;
            return 1;
        }
        
        // Short message for direct RSA encryption
        std::string shortMessage = "RSA encryption test with Crypto++";
        std::cout << "\nShort message: " << shortMessage << std::endl;
        
        // Encrypt the short message directly with RSA
        try {
            std::string rsaCiphertext = RSAEncrypt(shortMessage, publicKey);
            std::cout << "RSA ciphertext (Base64): " << Base64Encode(rsaCiphertext) << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "RSA encryption failed: " << e.what() << std::endl;
        }
        
        // Longer message for hybrid encryption
        std::string longMessage = "This is a longer message that exceeds the maximum size for direct RSA encryption. "
                                 "In practice, messages of any significant length should use hybrid encryption, "
                                 "where RSA is used to encrypt a random symmetric key, and the symmetric key is used "
                                 "to encrypt the actual message. This approach combines the security of asymmetric "
                                 "cryptography with the efficiency of symmetric cryptography.";
        std::cout << "\nLong message: " << longMessage << std::endl;
        
        // Encrypt the long message using hybrid encryption
        std::string hybridCiphertext = HybridEncrypt(longMessage, publicKey);
        std::cout << "Hybrid ciphertext length: " << hybridCiphertext.size() << " bytes" << std::endl;
        std::cout << "Hybrid ciphertext (Base64, first 100 chars): " 
                  << Base64Encode(hybridCiphertext).substr(0, 100) << "..." << std::endl;
        
        // Save the encrypted data to files
        StringSource ss1(rsaCiphertext, true, new FileSink("rsa_encrypted.bin"));
        StringSource ss2(hybridCiphertext, true, new FileSink("hybrid_encrypted.bin"));
        
        std::cout << "\nEncrypted data saved to 'rsa_encrypted.bin' and 'hybrid_encrypted.bin'" << std::endl;
        
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

## RSA Encryption Schemes in Crypto++

Crypto++ provides several classes for RSA encryption with different padding schemes:

1. **RSAES_PKCS1v15_Encryptor**: Uses PKCS#1 v1.5 padding
   ```cpp
   RSAES_PKCS1v15_Encryptor encryptor(publicKey);
   ```

2. **RSAES_OAEP_SHA_Encryptor**: Uses OAEP padding with SHA-1
   ```cpp
   RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
   ```

3. **RSAES_OAEP_SHA256_Encryptor**: Uses OAEP padding with SHA-256 (more secure)
   ```cpp
   RSAES_OAEP_SHA256_Encryptor encryptor(publicKey);
   ```

## Best Practices for RSA Encryption

1. **Use OAEP Padding**: PKCS#1 v1.5 padding has known vulnerabilities. Use OAEP padding with a strong hash function like SHA-256 for new applicatio
(Content truncated due to size limit. Use line ranges to read in chunks)