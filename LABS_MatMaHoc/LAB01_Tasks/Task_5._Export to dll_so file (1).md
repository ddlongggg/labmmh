Below is a **complete Markdown guide** for **Task 5: Export AES functions to a shared library (`.dll` / `.so`)**.
It shows how to **separate header and implementation**, export functions, and compile the library on **Linux and Windows**.

You can save this as:

```text
Task_5_Export_AES_to_DLL_SO.md
```

---

# Task 5 — Export AES Crypto++ Functions to DLL / SO Library

This task demonstrates how to package the AES encryption functionality developed in previous tasks into a **reusable shared library**.

Supported platforms:

* **Linux / macOS** → `.so`
* **Windows** → `.dll`

The exported library allows other programs to call AES encryption functions without recompiling the crypto code.

---

# 1. Project Structure

Recommended directory layout:

```
aeslib/
│
├── aeslib.h        # public header
├── aeslib.cpp      # library implementation
├── aescli.cpp      # optional CLI example
│
├── build/
│
└── README.md
```

---

# 2. Public Header File

File:

```
aeslib.h
```

This header exposes the **API exported from the library**.

```cpp
#ifndef AESLIB_H
#define AESLIB_H

#include <string>

#ifdef _WIN32
    #ifdef AESLIB_EXPORTS
        #define AESLIB_API __declspec(dllexport)
    #else
        #define AESLIB_API __declspec(dllimport)
    #endif
#else
    #define AESLIB_API
#endif

// AES key generation
AESLIB_API void GenerateAESKey(const std::string& file, const std::string& format);

// AES encryption
AESLIB_API void AESEncryptFile(
    const std::string& mode,
    const std::string& keyFormat,
    const std::string& keyFile,
    const std::string& inputFile,
    const std::string& outputFile
);

// AES decryption
AESLIB_API void AESDecryptFile(
    const std::string& mode,
    const std::string& keyFormat,
    const std::string& keyFile,
    const std::string& inputFile,
    const std::string& outputFile
);

#endif
```

---

# 3. Library Implementation

File:

```
aeslib.cpp
```

```cpp
#include "aeslib.h"

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>

#include <fstream>
#include <stdexcept>

using namespace CryptoPP;

//////////////////////////////////////////////////////////////
// Key Load / Save
//////////////////////////////////////////////////////////////

void SaveHex(const std::string& file,const SecByteBlock& key,const SecByteBlock& iv)
{
    std::string keyHex,ivHex;

    StringSource(key,key.size(),true,new HexEncoder(new StringSink(keyHex),false));
    StringSource(iv,iv.size(),true,new HexEncoder(new StringSink(ivHex),false));

    std::ofstream out(file);
    out<<"KEY="<<keyHex<<"\n";
    out<<"IV="<<ivHex<<"\n";
}

void LoadHex(const std::string& file,SecByteBlock& key,SecByteBlock& iv)
{
    std::ifstream in(file);

    std::string line1,line2;

    getline(in,line1);
    getline(in,line2);

    std::string keyHex=line1.substr(4);
    std::string ivHex=line2.substr(3);

    key.CleanNew(AES::DEFAULT_KEYLENGTH);
    iv.CleanNew(AES::BLOCKSIZE);

    StringSource(keyHex,true,new HexDecoder(new ArraySink(key,key.size())));
    StringSource(ivHex,true,new HexDecoder(new ArraySink(iv,iv.size())));
}

//////////////////////////////////////////////////////////////
// Generate Key
//////////////////////////////////////////////////////////////

void GenerateAESKey(const std::string& file,const std::string& format)
{
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);

    prng.GenerateBlock(key,key.size());
    prng.GenerateBlock(iv,iv.size());

    if(format=="hex")
        SaveHex(file,key,iv);
    else
        throw std::runtime_error("Unsupported key format");
}

//////////////////////////////////////////////////////////////
// Generic Encryption
//////////////////////////////////////////////////////////////

template<class MODE>
void EncryptFile(const std::string& in,const std::string& out,const SecByteBlock& key,const SecByteBlock& iv)
{
    MODE enc;
    enc.SetKeyWithIV(key,key.size(),iv);

    FileSource fs(in.c_str(),true,
        new StreamTransformationFilter(enc,
            new FileSink(out.c_str())
        )
    );
}

template<class MODE>
void DecryptFile(const std::string& in,const std::string& out,const SecByteBlock& key,const SecByteBlock& iv)
{
    MODE dec;
    dec.SetKeyWithIV(key,key.size(),iv);

    FileSource fs(in.c_str(),true,
        new StreamTransformationFilter(dec,
            new FileSink(out.c_str())
        )
    );
}

//////////////////////////////////////////////////////////////
// Encryption Dispatcher
//////////////////////////////////////////////////////////////

AESLIB_API void AESEncryptFile(
    const std::string& mode,
    const std::string& keyFormat,
    const std::string& keyFile,
    const std::string& inputFile,
    const std::string& outputFile
)
{
    SecByteBlock key,iv;

    LoadHex(keyFile,key,iv);

    if(mode=="cbc")
        EncryptFile<CBC_Mode<AES>::Encryption>(inputFile,outputFile,key,iv);

    else if(mode=="ctr")
        EncryptFile<CTR_Mode<AES>::Encryption>(inputFile,outputFile,key,iv);

    else
        throw std::runtime_error("Unsupported AES mode");
}

//////////////////////////////////////////////////////////////
// Decryption Dispatcher
//////////////////////////////////////////////////////////////

AESLIB_API void AESDecryptFile(
    const std::string& mode,
    const std::string& keyFormat,
    const std::string& keyFile,
    const std::string& inputFile,
    const std::string& outputFile
)
{
    SecByteBlock key,iv;

    LoadHex(keyFile,key,iv);

    if(mode=="cbc")
        DecryptFile<CBC_Mode<AES>::Decryption>(inputFile,outputFile,key,iv);

    else if(mode=="ctr")
        DecryptFile<CTR_Mode<AES>::Decryption>(inputFile,outputFile,key,iv);

    else
        throw std::runtime_error("Unsupported AES mode");
}
```

---

# 4. Build Shared Library

## Linux / macOS (.so)

Compile shared object:

```bash
g++ -fPIC -shared aeslib.cpp -lcryptopp -o libaeslib.so
```

Output:

```
libaeslib.so
```

---

## Windows (.dll)

Compile DLL:

```bash
g++ -shared -DAESLIB_EXPORTS aeslib.cpp -lcryptopp -o aeslib.dll
```

Output:

```
aeslib.dll
```

---

# 5. Example Program Using the Library

File:

```
aescli.cpp
```

```cpp
#include "aeslib.h"

#include <iostream>

int main()
{
    GenerateAESKey("key.hex","hex");

    AESEncryptFile(
        "cbc",
        "hex",
        "key.hex",
        "input.txt",
        "encrypted.bin"
    );

    AESDecryptFile(
        "cbc",
        "hex",
        "key.hex",
        "encrypted.bin",
        "output.txt"
    );

    std::cout<<"Encryption and Decryption complete\n";
}
```

Compile:

```bash
g++ aescli.cpp -L. -laeslib -lcryptopp -o aescli
```

---

# 6. Run Example

Linux:

```
export LD_LIBRARY_PATH=.
./aescli
```

Windows:

```
aescli.exe
```

---

# 7. Advantages of Using a Shared Library

| Feature          | Benefit                                 |
| ---------------- | --------------------------------------- |
| Reusability      | Multiple programs can reuse crypto code |
| Modular design   | Separate API and implementation         |
| Faster builds    | No recompiling Crypto++ logic           |
| Language binding | Can be used from Python / C / Rust      |

---

# 8. Future Extensions

The shared library can be expanded to support:

* AES-GCM authenticated encryption
* RSA encryption
* SHA hashing
* HMAC authentication
* PBKDF2 password-based key derivation
* Secure key containers

Example extended API:

```
AES_GCM_EncryptFile()
AES_GCM_DecryptFile()
GenerateRSAKeyPair()
SHA256_FileHash()
```

---
