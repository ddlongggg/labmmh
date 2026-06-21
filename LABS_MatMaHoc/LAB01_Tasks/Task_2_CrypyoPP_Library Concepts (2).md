# Crypto++ Library: Pipeline and Source-Sink Structure Examples

This guide demonstrates how to use **Crypto++**'s pipeline architecture with different types of sources and sinks:

- 📜 `StringSource` / `StringSink`
- 📄 `FileSource` / `FileSink`
- 📦 `ArraySource` / `ArraySink`

All examples use **AES encryption in CBC mode**.


## 1️⃣ StringSource → AES Encrypt → StringSink

```cpp
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <filters.h>
#include <hex.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool prng;
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];
    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));

    std::string plaintext = "Crypto++ StringSource example";
    std::string ciphertext, hexEncoded;

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(ciphertext)
        )
    );

    StringSource(ciphertext, true,
        new HexEncoder(new StringSink(hexEncoded))
    );

    std::cout << "Encrypted (hex): " << hexEncoded << std::endl;
    return 0;
}
```

---

## 2️⃣ FileSource → AES Encrypt → FileSink

```cpp
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <filters.h>
#include <files.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool prng;
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];
    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);

    FileSource("plaintext.txt", true,
        new StreamTransformationFilter(encryptor,
            new FileSink("ciphertext.bin")
        )
    );

    std::cout << "File encrypted and saved as ciphertext.bin" << std::endl;
    return 0;
}
```

---

## 3️⃣ ArraySource → AES Encrypt → ArraySink

```cpp
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <filters.h>
#include <secblock.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool prng;
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];
    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));

    byte input[] = "Array input";
    byte output[64];
    size_t outputLen = 0;

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);

    ArraySink sink(output, sizeof(output));
    ArraySource(input, sizeof(input) - 1, true,
        new StreamTransformationFilter(encryptor,
            new Redirector(sink)
        )
    );

    outputLen = sink.TotalPutLength();

    std::cout << "Encrypted " << outputLen << " bytes using ArraySource → ArraySink." << std::endl;
    return 0;
}
```

---

## ✅ Summary

| Type        | Source         | Sink         |
|-------------|----------------|--------------|
| **String**  | `StringSource` | `StringSink` |
| **File**    | `FileSource`   | `FileSink`   |
| **Array**   | `ArraySource`  | `ArraySink`  |

Each pair can be combined with Crypto++ **filters** like `StreamTransformationFilter`, `HexEncoder`, and others to create powerful pipelines for cryptographic processing.
