#include "AES_XTS.h"
#include <cstring>
#include <stdexcept>

namespace AES_XTS {

    void MultiplyByX(uint8_t block[16]) {
        uint8_t carryIn = 0;
        for (int i = 0; i < 16; i++) {
            uint8_t nextCarry = (block[i] >> 7) & 1;
            block[i] = (block[i] << 1) | carryIn;
            carryIn = nextCarry;
        }
        if (carryIn) {
            block[0] ^= 0x87;
        }
    }

    void ProcessBuffer(const AESCore::AES& aes1, const AESCore::AES& aes2, 
                       const uint8_t tweak[16], const uint8_t* in, uint8_t* out, size_t length, bool isEncrypt) {
        if (length % 16 != 0) {
            throw std::runtime_error("XTS mode partial blocks (Ciphertext Stealing) not implemented. Length must be a multiple of 16.");
        }
        uint8_t T[16];
        aes2.EncryptBlock(tweak, T); 

        size_t offset = 0;
        uint8_t PP[16];
        uint8_t CC[16];

        while (offset < length) {
            for (int i = 0; i < 16; i++) {
                PP[i] = in[offset + i] ^ T[i];
            }

            if (isEncrypt) {
                aes1.EncryptBlock(PP, CC);
            } else {
                aes1.DecryptBlock(PP, CC);
            }

            for (int i = 0; i < 16; i++) {
                out[offset + i] = CC[i] ^ T[i];
            }
            offset += 16;
            MultiplyByX(T);
        }
    }

}
