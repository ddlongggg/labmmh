#pragma once
#include "AESCore.h"
#include <cstdint>
#include <vector>

namespace AES_XTS {

    // Multiplies a 16-byte polynomial by x in GF(2^128)
    void MultiplyByX(uint8_t block[16]);

    // Encrypts or Decrypts using XTS mode.
    // key1 and key2 must both be the same length (16, 24, or 32 bytes).
    // The total key size for AES-128-XTS is 32 bytes (16 for key1, 16 for key2).
    void ProcessBuffer(const AESCore::AES& aes1, const AESCore::AES& aes2, 
                       const uint8_t tweak[16], const uint8_t* in, uint8_t* out, size_t length, bool isEncrypt);

}
