#pragma once

#include <cstdint>
#include <vector>
#include <stdexcept>

// Platform specific includes for intrinsics
#if defined(_MSC_VER)
    #include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
    #include <x86intrin.h>
    #include <cpuid.h>
#endif

namespace AESCore_NI {

    // Check if the current CPU supports AES-NI instructions
    bool CheckAESNI();

    class AES_NI {
    public:
        // Key lengths: 16 (AES-128), 24 (AES-192), 32 (AES-256)
        AES_NI(const uint8_t* key, size_t keyLen);
        ~AES_NI();

        // Encrypts exactly one 16-byte block
        void EncryptBlock(const uint8_t in[16], uint8_t out[16]) const;

    private:
        int Nr; // Number of rounds
        std::vector<__m128i> roundKeys;

        void KeyExpansion128(const uint8_t* key);
        void KeyExpansion192(const uint8_t* key);
        void KeyExpansion256(const uint8_t* key);
    };

}
