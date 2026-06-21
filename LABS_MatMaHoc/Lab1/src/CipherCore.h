#pragma once

#include <string>
#include <cryptopp/secblock.h>

namespace CipherCore {

    struct CipherOptions {
        std::string mode;
        CryptoPP::SecByteBlock key;
        CryptoPP::SecByteBlock iv;
        bool allowEcb = false;
        bool isAead = false;
        bool noPadding = false;
        std::string aad = "";
    };

    void Encrypt(const std::string& inFile, const std::string& outFile, const CipherOptions& options, CryptoPP::SecByteBlock& outTag);
    void Decrypt(const std::string& inFile, const std::string& outFile, const CipherOptions& options, const CryptoPP::SecByteBlock& inTag);

}
