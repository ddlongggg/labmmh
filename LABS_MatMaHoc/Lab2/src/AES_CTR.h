#pragma once

#include "AESCore.h"
#include "AESCore_NI.h"
#include <cstdint>
#include <vector>

namespace AES_CTR {

    void IncrementCounter(uint8_t counter[16]);

    // Encrypts or Decrypts using CTR mode. 
    // In CTR mode, encryption and decryption are identical.
    void ProcessBuffer(const AESCore::AES& aes, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t length);
    void ProcessBuffer(const AESCore_NI::AES_NI& aes, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t length);

}
