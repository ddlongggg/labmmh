#pragma once

#include <cstdint>
#include <vector>
#include <stdexcept>

namespace AESCore {

    class AES {
    public:
        // Key lengths: 16 (AES-128), 24 (AES-192), 32 (AES-256)
        AES(const uint8_t* key, size_t keyLen);
        ~AES();

        // Encrypts exactly one 16-byte block
        void EncryptBlock(const uint8_t in[16], uint8_t out[16]) const;
        
        // Decrypts exactly one 16-byte block
        void DecryptBlock(const uint8_t in[16], uint8_t out[16]) const;

    private:
        int Nb; // Number of columns (always 4 for AES)
        int Nk; // Key length in words
        int Nr; // Number of rounds

        std::vector<uint32_t> roundKeys;

        void KeyExpansion(const uint8_t* key);
        
        // FIPS-197 Core Functions
        void SubBytes(uint8_t state[4][4]) const;
        void ShiftRows(uint8_t state[4][4]) const;
        void MixColumns(uint8_t state[4][4]) const;
        void AddRoundKey(uint8_t state[4][4], int round) const;

        // FIPS-197 Inverse Functions
        void InvSubBytes(uint8_t state[4][4]) const;
        void InvShiftRows(uint8_t state[4][4]) const;
        void InvMixColumns(uint8_t state[4][4]) const;

        // GF(2^8) math helpers
        uint8_t GMul(uint8_t a, uint8_t b) const;
    };

}
