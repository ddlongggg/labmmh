# Guide 2: RSA Key Generation Using Crypto++

Task 2.1 Run all demo codes, include full and part codes
Task 2.2 Revise code to set any public key (p, q, n, e, d, ...)

## Introduction

This guide demonstrates how to generate RSA key pairs using the Crypto++ library and save them in both PEM and DER formats. RSA key generation is a fundamental operation in asymmetric cryptography, creating the public and private key pairs needed for encryption, decryption, and digital signatures.

## Prerequisites

- Crypto++ library installed (version 8.6.0 or later)
- Basic understanding of RSA cryptography and key formats (see Guide 1)
- C++ development environment

## RSA Key Generation Concepts

Before diving into the code, let's understand some key concepts:

1. **Key Size**: The size of an RSA key is measured in bits. Common sizes are 2048, 3072, and 4096 bits. Larger keys provide better security but require more computational resources.

2. **Key Components**:
   - **Modulus (n)**: The product of two large prime numbers (p and q)
   - **Public Exponent (e)**: A number relatively prime to (p-1)(q-1), commonly 65537, 17
   - **Private Exponent (d)**: The modular multiplicative inverse of e modulo (p-1)(q-1)
   - **Prime Factors (p, q)**: The two large prime numbers whose product is n
   - **Additional CRT Values**: Values that speed up private key operations using the Chinese Remainder Theorem

3. **Random Number Generator**: A cryptographically secure random number generator is essential for generating strong keys.

## Basic RSA Key Generation with Crypto++

Let's start with a simple example of generating RSA keys using Crypto++:

```cpp
#include <iostream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

int main() {
    // Create a random number generator
    AutoSeededRandomPool rng;
    
    // Generate RSA keys
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 3072);
    
    // Extract the public key from the private key
    RSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);
    
    // Verify the keys
    bool result = privateKey.Validate(rng, 3);
    if (!result) {
        std::cerr << "Private key validation failed" << std::endl;
        return 1;
    }
    
    result = publicKey.Validate(rng, 3);
    if (!result) {
        std::cerr << "Public key validation failed" << std::endl;
        return 1;
    }
    
    std::cout << "RSA keys generated and validated successfully." << std::endl;
    
    return 0;
}
```

This code:
1. Creates an `AutoSeededRandomPool` for secure random number generation
2. Generates a 3072-bit RSA private key
3. Extracts the public key from the private key
4. Validates both keys to ensure they're properly formed

## Saving Keys in DER Format

To save the generated keys in DER format, we need to use Crypto++'s `ByteQueue` and `FileSink` classes:

```cpp
#include <cryptopp/queue.h>
#include <cryptopp/files.h>

void SavePrivateKeyToDERFile(const RSA::PrivateKey& key, const std::string& filename) {
    ByteQueue queue;
    key.Save(queue);
    
    FileSink file(filename.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
}

void SavePublicKeyToDERFile(const RSA::PublicKey& key, const std::string& filename) {
    ByteQueue queue;
    key.Save(queue);
    
    FileSink file(filename.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
}
```

Usage:
```cpp
SavePrivateKeyToDERFile(privateKey, "private_key.der");
SavePublicKeyToDERFile(publicKey, "public_key.der");
```

## Converting DER to PEM Format

Crypto++ doesn't natively support PEM format, but we can convert DER to PEM by:
1. Base64 encoding the DER data
2. Adding appropriate headers and footers
3. Formatting with line breaks

Here's a function to convert DER to PEM:

```cpp
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <fstream>

void DERToPEM(const std::string& derFilename, const std::string& pemFilename, 
              const std::string& header, const std::string& footer) {
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
}
```

Usage:
```cpp
// Convert private key from DER to PEM
DERToPEM("private_key.der", "private_key.pem", 
         "-----BEGIN RSA PRIVATE KEY-----", 
         "-----END RSA PRIVATE KEY-----");

// Convert public key from DER to PEM
DERToPEM("public_key.der", "public_key.pem", 
         "-----BEGIN PUBLIC KEY-----", 
         "-----END PUBLIC KEY-----");
```

## Complete Example: Generating and Saving RSA Keys

Let's put everything together in a complete example:

```cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

// Function to save a key to a DER file
template<class KEY>
void SaveKeyToDERFile(const KEY& key, const std::string& filename) {
    ByteQueue queue;
    key.Save(queue);
    
    FileSink file(filename.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
}

// Function to convert DER to PEM
void DERToPEM(const std::string& derFilename, const std::string& pemFilename, 
              const std::string& header, const std::string& footer) {
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
}

int main() {
    try {
        std::cout << "Generating RSA keys..." << std::endl;
        
        // Create a random number generator
        AutoSeededRandomPool rng;
        
        // Generate RSA keys (3072 bits for good security)
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, 3072);
        
        // Extract the public key from the private key
        RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);
        
        // Validate the keys
        bool result = privateKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Private key validation failed" << std::endl;
            return 1;
        }
        
        result = publicKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Public key validation failed" << std::endl;
            return 1;
        }
        
        std::cout << "Keys generated and validated successfully." << std::endl;
        
        // Save keys in DER format
        std::cout << "Saving keys in DER format..." << std::endl;
        SaveKeyToDERFile(privateKey, "private_key.der");
        SaveKeyToDERFile(publicKey, "public_key.der");
        
        // Convert to PEM format
        std::cout << "Converting keys to PEM format..." << std::endl;
        DERToPEM("private_key.der", "private_key.pem", 
                 "-----BEGIN RSA PRIVATE KEY-----", 
                 "-----END RSA PRIVATE KEY-----");
        
        DERToPEM("public_key.der", "public_key.pem", 
                 "-----BEGIN PUBLIC KEY-----", 
                 "-----END PUBLIC KEY-----");
        
        std::cout << "Keys saved in both DER and PEM formats." << std::endl;
        
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

## Using the PEM Pack (Alternative Approach)

As mentioned in Guide 1, Crypto++ doesn't natively support PEM format, but there's an add-on called the "PEM Pack" that provides this functionality. Here's how to use it:

1. Download the PEM Pack files from the Crypto++ Wiki
2. Add them to your project
3. Use the provided functions to work with PEM files directly

Example using the PEM Pack:

```cpp
#include <cryptopp/pem.h> // From PEM Pack

// Save private key directly to PEM
void SavePrivateKeyToPEM(const RSA::PrivateKey& key, const std::string& filename) {
    FileSink file(filename.c_str());
    PEM_Save(file, key);
}

// Save public key directly to PEM
void SavePublicKeyToPEM(const RSA::PublicKey& key, const std::string& filename) {
    FileSink file(filename.c_str());
    PEM_Save(file, key);
}

// Load private key from PEM
void LoadPrivateKeyFromPEM(RSA::PrivateKey& key, const std::string& filename) {
    FileSource file(filename.c_str(), true);
    PEM_Load(file, key);
}

// Load public key from PEM
void LoadPublicKeyFromPEM(RSA::PublicKey& key, const std::string& filename) {
    FileSource file(filename.c_str(), true);
    PEM_Load(file, key);
}
```

## Key Generation Parameters

When generating RSA keys, you can customize several parameters:

1. **Key Size**: The most important parameter, determining the security level.
   ```cpp
   privateKey.GenerateRandomWithKeySize(rng, 4096); // For a 4096-bit key
   ```

2. **Public Exponent**: By default, Crypto++ uses 65537 (0x10001), which is a good choice for most applications. If you need to use a different value:
   ```cpp
   // Create an InvertibleRSAFunction object
   InvertibleRSAFunction params;
   params.GenerateRandomWithKeySize(rng, 3072);
   
   // Set a custom public exponent (e.g., 3)
   // Note: Small exponents like 3 can be less secure in some scenarios
   params.SetPublicExponent(3);
   
   // Create the keys from the parameters
   RSA::PrivateKey privateKey(params);
   RSA::PublicKey publicKey(params);
   ```

## Best Practices for RSA Key Generation

1. **Key Size**: Use at least 2048 bits for short-term security, 3072 bits for medium-term security, and 4096 bits for long-term security.

2. **Random Number Generator**: Always use a cryptographically secure random number generator. Crypto++'s `AutoSeededRandomPool` is a good choice for most applications.

3. **Key Validation**: Always validate keys after generation to ensure they're properly formed.

4. **Key Storage**: Store private keys securely, preferably encrypted when at rest.

5. **Public Exponent**: The default value of 65537 (0x10001) is a good choice for most applications.

## Conclusion

This guide has demonstrated how to generate RSA key pairs using the Crypto++ library and save them in both DER and PEM formats. In the next guide, we'll explore how to use these keys for RSA encryption operations.

## Compilation and Execution

msvc/g++/clang++