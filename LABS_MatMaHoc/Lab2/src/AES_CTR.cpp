#include "AES_CTR.h"
#include <cstring>
#include <algorithm>

namespace AES_CTR {

    void IncrementCounter(uint8_t counter[16]) {
        for (int i = 15; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0) {
                break; 
            }
        }
    }

    void ProcessBuffer(const AESCore::AES& aes, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t length) {
        uint8_t counter[16];
        std::memcpy(counter, iv, 16);
        uint8_t keystream[16];
        size_t offset = 0;

        while (offset < length) {
            aes.EncryptBlock(counter, keystream);
            size_t bytesToXor = std::min((size_t)16, length - offset);
            for (size_t i = 0; i < bytesToXor; i++) {
                out[offset + i] = in[offset + i] ^ keystream[i];
            }
            offset += bytesToXor;
            IncrementCounter(counter);
        }
    }

    void ProcessBuffer(const AESCore_NI::AES_NI& aes, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t length) {
        uint8_t counter[16];
        std::memcpy(counter, iv, 16);

        uint8_t keystream[16];
        size_t offset = 0;

        while (offset < length) {
            aes.EncryptBlock(counter, keystream);
            size_t bytesToXor = std::min((size_t)16, length - offset);
            for (size_t i = 0; i < bytesToXor; i++) {
                out[offset + i] = in[offset + i] ^ keystream[i];
            }
            offset += bytesToXor;
            IncrementCounter(counter);
        }
    }

}
