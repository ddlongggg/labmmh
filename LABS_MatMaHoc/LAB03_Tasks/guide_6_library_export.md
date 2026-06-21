# Guide 6: Exporting RSA Functionality to a Shared Library (DLL/SO)

## Introduction

This guide demonstrates how to export the RSA functionality developed in previous guides to a shared library (DLL on Windows or SO on Linux/macOS). Creating a shared library allows the RSA functionality to be used by multiple applications and programming languages, promoting code reuse and modularity.

## Prerequisites

- Crypto++ library installed (version 8.6.0 or later)
- Understanding of RSA cryptography concepts
- C++ development environment
- Familiarity with shared library concepts

## Shared Library Concepts

Before diving into the implementation, let's understand some key concepts related to shared libraries:

1. **Shared Library**: A library that is loaded dynamically at runtime rather than linked statically at compile time. On Windows, these are Dynamic Link Libraries (DLLs), and on Linux/macOS, they are Shared Objects (SOs).

2. **API Design**: When creating a shared library, it's important to design a clean, stable API that can be used by client applications.

3. **Symbol Visibility**: Controlling which functions and classes are exported from the library and which remain internal.

4. **ABI Compatibility**: Ensuring that the Application Binary Interface remains compatible across different versions of the library.

5. **Cross-Platform Considerations**: Different platforms have different requirements for shared libraries.

## Designing the Library API

Let's design a clean C API for our RSA library. Using a C API (rather than C++) ensures maximum compatibility with other languages and platforms:

```c
// rsa_lib.h - Public API header

#ifndef RSA_LIB_H
#define RSA_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

// Define export macro for different platforms
#ifdef _WIN32
    #ifdef RSA_LIB_EXPORTS
        #define RSA_API __declspec(dllexport)
    #else
        #define RSA_API __declspec(dllimport)
    #endif
#else
    #define RSA_API __attribute__((visibility("default")))
#endif

// Opaque handle types
typedef struct RSAPublicKey_st* RSAPublicKeyHandle;
typedef struct RSAPrivateKey_st* RSAPrivateKeyHandle;

// Error codes
typedef enum {
    RSA_SUCCESS = 0,
    RSA_ERROR_INVALID_PARAMETER = -1,
    RSA_ERROR_MEMORY_ALLOCATION = -2,
    RSA_ERROR_KEY_GENERATION = -3,
    RSA_ERROR_KEY_VALIDATION = -4,
    RSA_ERROR_ENCRYPTION = -5,
    RSA_ERROR_DECRYPTION = -6,
    RSA_ERROR_FILE_IO = -7,
    RSA_ERROR_BUFFER_TOO_SMALL = -8,
    RSA_ERROR_INVALID_FORMAT = -9,
    RSA_ERROR_UNKNOWN = -99
} RSAStatusCode;

// Padding schemes
typedef enum {
    RSA_PADDING_PKCS1 = 1,
    RSA_PADDING_OAEP = 2
} RSAPaddingScheme;

// Output formats
typedef enum {
    RSA_FORMAT_BINARY = 1,
    RSA_FORMAT_BASE64 = 2,
    RSA_FORMAT_HEX = 3
} RSAOutputFormat;

// Key generation
RSA_API RSAStatusCode RSA_GenerateKeyPair(
    unsigned int keySize,
    const char* privateKeyFile,
    const char* publicKeyFile,
    int usePEM
);

// Key loading
RSA_API RSAStatusCode RSA_LoadPublicKey(
    const char* filename,
    RSAPublicKeyHandle* keyHandle
);

RSA_API RSAStatusCode RSA_LoadPrivateKey(
    const char* filename,
    RSAPrivateKeyHandle* keyHandle
);

// Key freeing
RSA_API void RSA_FreePublicKey(RSAPublicKeyHandle keyHandle);
RSA_API void RSA_FreePrivateKey(RSAPrivateKeyHandle keyHandle);

// Encryption
RSA_API RSAStatusCode RSA_Encrypt(
    RSAPublicKeyHandle publicKey,
    const unsigned char* data,
    size_t dataLength,
    unsigned char* encryptedData,
    size_t* encryptedDataLength,
    RSAPaddingScheme paddingScheme,
    int useHybrid
);

// Decryption
RSA_API RSAStatusCode RSA_Decrypt(
    RSAPrivateKeyHandle privateKey,
    const unsigned char* encryptedData,
    size_t encryptedDataLength,
    unsigned char* decryptedData,
    size_t* decryptedDataLength,
    RSAPaddingScheme paddingScheme,
    int useHybrid
);

// File-based operations
RSA_API RSAStatusCode RSA_EncryptFile(
    RSAPublicKeyHandle publicKey,
    const char* inputFile,
    const char* outputFile,
    RSAPaddingScheme paddingScheme,
    RSAOutputFormat outputFormat,
    int useHybrid
);

RSA_API RSAStatusCode RSA_DecryptFile(
    RSAPrivateKeyHandle privateKey,
    const char* inputFile,
    const char* outputFile,
    RSAPaddingScheme paddingScheme,
    RSAOutputFormat inputFormat,
    int useHybrid
);

// Utility functions
RSA_API const char* RSA_GetErrorMessage(RSAStatusCode code);
RSA_API size_t RSA_GetMaxPlaintextLength(RSAPublicKeyHandle publicKey, RSAPaddingScheme paddingScheme);

#ifdef __cplusplus
}
#endif

#endif // RSA_LIB_H
```

## Implementing the Library

Now let's implement the library using our existing RSA code:

```cpp
// rsa_lib.cpp - Implementation file

#include "rsa_lib.h"
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <fstream>
#include <string>
#include <vector>
#include <map>

using namespace CryptoPP;

// Define the opaque handle structures
struct RSAPublicKey_st {
    RSA::PublicKey key;
};

struct RSAPrivateKey_st {
    RSA::PrivateKey key;
};

// Error message mapping
static std::map<RSAStatusCode, const char*> errorMessages = {
    {RSA_SUCCESS, "Success"},
    {RSA_ERROR_INVALID_PARAMETER, "Invalid parameter"},
    {RSA_ERROR_MEMORY_ALLOCATION, "Memory allocation failed"},
    {RSA_ERROR_KEY_GENERATION, "Key generation failed"},
    {RSA_ERROR_KEY_VALIDATION, "Key validation failed"},
    {RSA_ERROR_ENCRYPTION, "Encryption failed"},
    {RSA_ERROR_DECRYPTION, "Decryption failed"},
    {RSA_ERROR_FILE_IO, "File I/O error"},
    {RSA_ERROR_BUFFER_TOO_SMALL, "Buffer too small"},
    {RSA_ERROR_INVALID_FORMAT, "Invalid format"},
    {RSA_ERROR_UNKNOWN, "Unknown error"}
};

// Utility function to save a key to a DER file
template<class KEY>
static bool SaveKeyToDERFile(const KEY& key, const std::string& filename) {
    try {
        ByteQueue queue;
        key.Save(queue);
        
        FileSink file(filename.c_str());
        queue.CopyTo(file);
        file.MessageEnd();
        return true;
    } catch (...) {
        return false;
    }
}

// Utility function to convert DER to PEM
static bool DERToPEM(const std::string& derFilename, const std::string& pemFilename, 
                    const std::string& header, const std::string& footer) {
    try {
        // Read DER file
        std::ifstream derFile(derFilename, std::ios::binary);
        std::vector<char> derData((std::istreambuf_iterator<char>(derFile)),
                                std::istreambuf_iterator<char>());
        derFile.close();
        
        // Base64 encode
        std::string base64Data;
        StringSource ss(reinterpret_cast<const byte*>(derData.data()), derData.size(), true,
            new Base64Encoder(
                new StringSink(base64Data), true, 64
            )
        );
        
        // Write PEM file
        std::ofstream pemFile(pemFilename);
        pemFile << header << std::endl;
        pemFile << base64Data;
        pemFile << footer << std::endl;
        pemFile.close();
        return true;
    } catch (...) {
        return false;
    }
}

// Implementation of key generation
RSA_API RSAStatusCode RSA_GenerateKeyPair(
    unsigned int keySize,
    const char* privateKeyFile,
    const char* publicKeyFile,
    int usePEM
) {
    if (!privateKeyFile || !publicKeyFile || keySize < 1024) {
        return RSA_ERROR_INVALID_PARAMETER;
    }
    
    try {
        // Create a random number generator
        AutoSeededRandomPool rng;
        
        // Generate RSA keys
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, keySize);
        
        // Extract the public key from the private key
        RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);
        
        // Validate the keys
        bool result = privateKey.Validate(rng, 3);
        if (!result) {
            return RSA_ERROR_KEY_VALIDATION;
        }
        
        result = publicKey.Validate(rng, 3);
        if (!result) {
            return RSA_ERROR_KEY_VALIDATION;
        }
        
        // Determine filenames
        std::string privateKeyDer = std::string(privateKeyFile) + (usePEM ? ".der" : "");
        std::string publicKeyDer = std::string(publicKeyFile) + (usePEM ? ".der" : "");
        
        // Save keys in DER format
        if (!SaveKeyToDERFile(privateKey, usePEM ? privateKeyDer : privateKeyFile)) {
            return RSA_ERROR_FILE_IO;
        }
        
        if (!SaveKeyToDERFile(publicKey, usePEM ? publicKeyDer : publicKeyFile)) {
            return RSA_ERROR_FILE_IO;
        }
        
        // Convert to PEM format if requested
        if (usePEM) {
            if (!DERToPEM(privateKeyDer, privateKeyFile, 
                         "-----BEGIN RSA PRIVATE KEY-----", 
                         "-----END RSA PRIVATE KEY-----")) {
                return RSA_ERROR_FILE_IO;
            }
            
            if (!DERToPEM(publicKeyDer, publicKeyFile, 
                         "-----BEGIN PUBLIC KEY-----", 
                         "-----END PUBLIC KEY-----")) {
                return RSA_ERROR_FILE_IO;
            }
        }
        
        return RSA_SUCCESS;
    } catch (const CryptoPP::Exception&) {
        return RSA_ERROR_KEY_GENERATION;
    } catch (const std::exception&) {
        return RSA_ERROR_UNKNOWN;
    } catch (...) {
        return RSA_ERROR_UNKNOWN;
    }
}

// Implementation of public key loading
RSA_API RSAStatusCode RSA_LoadPublicKey(
    const char* filename,
    RSAPublicKeyHandle* keyHandle
) {
    if (!filename || !keyHandle) {
        return RSA_ERROR_INVALID_PARAMETER;
    }
    
    try {
        *keyHandle = new RSAPublicKey_st();
        if (!*keyHandle) {
            return RSA_ERROR_MEMORY_ALLOCATION;
        }
        
        // Try loading as PEM
        bool isPEM = false;
        std::ifstream file(filename);
        std::string line, base64Data;
        bool inKey = false;
        
        while (std::getline(file, line)) {
            if (line == "-----BEGIN PUBLIC KEY-----") {
                inKey = true;
                isPEM = true;
            } else if (line == "-----END PUBLIC KEY-----") {
                inKey = false;
            } else if (inKey) {
                base64Data += line;
            }
        }
        
        if (isPEM) {
            // Decode the Base64 data
            std::string derData;
            StringSource ss(base64Data, true,
                new Base64Decoder(
                    new StringSink(derData)
                )
            );
            
            // Load the key
            ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
            (*keyHandle)->key.Load(as);
        } else {
            // Try loading as DER
            FileSource fs(filename, true);
            (*keyHandle)->key.Load(fs);
        }
        
        // Validate the key
        AutoSeededRandomPool rng;
        if (!(*keyHandle)->key.Validate(rng, 3)) {
            delete *keyHandle;
            *keyHandle = nullptr;
            return RSA_ERROR_KEY_VALIDATION;
        }
        
        return RSA_SUCCESS;
    } catch (const CryptoPP::Exception&) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_FILE_IO;
    } catch (const std::exception&) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_UNKNOWN;
    } catch (...) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_UNKNOWN;
    }
}

// Implementation of private key loading
RSA_API RSAStatusCode RSA_LoadPrivateKey(
    const char* filename,
    RSAPrivateKeyHandle* keyHandle
) {
    if (!filename || !keyHandle) {
        return RSA_ERROR_INVALID_PARAMETER;
    }
    
    try {
        *keyHandle = new RSAPrivateKey_st();
        if (!*keyHandle) {
            return RSA_ERROR_MEMORY_ALLOCATION;
        }
        
        // Try loading as PEM
        bool isPEM = false;
        std::ifstream file(filename);
        std::string line, base64Data;
        bool inKey = false;
        
        while (std::getline(file, line)) {
            if (line == "-----BEGIN RSA PRIVATE KEY-----" || line == "-----BEGIN PRIVATE KEY-----") {
                inKey = true;
                isPEM = true;
            } else if (line == "-----END RSA PRIVATE KEY-----" || line == "-----END PRIVATE KEY-----") {
                inKey = false;
            } else if (inKey) {
                base64Data += line;
            }
        }
        
        if (isPEM) {
            // Decode the Base64 data
            std::string derData;
            StringSource ss(base64Data, true,
                new Base64Decoder(
                    new StringSink(derData)
                )
            );
            
            // Load the key
            ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
            (*keyHandle)->key.Load(as);
        } else {
            // Try loading as DER
            FileSource fs(filename, true);
            (*keyHandle)->key.Load(fs);
        }
        
        // Validate the key
        AutoSeededRandomPool rng;
        if (!(*keyHandle)->key.Validate(rng, 3)) {
            delete *keyHandle;
            *keyHandle = nullptr;
            return RSA_ERROR_KEY_VALIDATION;
        }
        
        return RSA_SUCCESS;
    } catch (const CryptoPP::Exception&) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_FILE_IO;
    } catch (const std::exception&) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_UNKNOWN;
    } catch (...) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_UNKNOWN;
    }
}

// Implementation of public key freeing
RSA_API void RSA_FreePublicKey(RSAPublicKeyHandle keyHandle) {
    if (keyHandle) {
        delete keyHandle;
    }
}

// Implementation of private key freeing
RSA_API void RSA_FreePrivateKey(RSAPrivateKeyHandle keyHandle) {
    if (keyHandle) {
        delete keyHandle;
    }
}

// Implementation of direct RSA encryption
static std::string RSAEncryptInternal(
    const std::string& plaintext,
    const RSA::PublicKey& publicKey,
    RSAPaddingScheme paddingScheme
) {
    AutoSeededRandomPool rng;
    
    // Create an encryptor with the specified padding
    PK_Encryptor* encryptor = nullptr;
    
    if (paddingScheme == RSA_PADDING_PKCS1) {
        encryptor = new RSAES_PKCS1v15_Encryptor(publicKey);
    } else {  // Default to OAEP
        encryptor = new RSAES_OAEP_SHA256_Encryptor(publicKey);
    }
    
    // Check if the message fits within the maximum size
    size_t maxPlaintextLength = encryptor->FixedMaxPlaintextLength();
    if (plaintext.length() > maxPlaintextLength) {
        delete encryptor;
        throw std::runtime_error("Message too long for RSA encryption");
    }
    
    // Perform encryption
    std::string ciphertext;
    StringSource ss(plaintext, true,
        new PK_EncryptorFilter(rng, *encryptor,
            new StringSink(ciphertext)
        )
    );
    
    delete encryptor;
    return ciphertext;
}

// Implementation of hybrid encryption
static std::string HybridEncryptInternal(
    const std::string& plaintext,
    const RSA::PublicKey& publicKey,
    RSAPaddingScheme paddingScheme
) {
    AutoSeededRandomPool rng;
    
    // Generate a random AES key
    byte aesKey[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(aesKey, sizeof(aesKey));
    rn
(Content truncated due to size limit. Use line ranges to read in chunks)