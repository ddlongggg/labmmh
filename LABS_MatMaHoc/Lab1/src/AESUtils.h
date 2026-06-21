#pragma once

#include <string>
#include <vector>
#include <cryptopp/secblock.h>

enum class KeyFormat {
    HEX,
    BIN
};

namespace AESUtils {
    // Generate AES Key + IV
    void GenerateAESKey(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv, size_t keySize = 32); // Default to AES-256

    // Save/Load keys
    void SaveKey(KeyFormat format, const std::string& file, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv);
    void LoadKey(KeyFormat format, const std::string& file, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);

    // Sidecar header (simple key-value save)
    void SaveSidecar(const std::string& file, const std::string& alg, const std::string& mode, const CryptoPP::SecByteBlock& iv, const std::string& aad = "", const CryptoPP::SecByteBlock& tag = CryptoPP::SecByteBlock());

    // Nonce tracking
    void CheckAndRecordNonce(const std::string& mode, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv);

    // Print Hex utility
    void PrintHex(const std::string& label, const CryptoPP::byte* data, size_t len);
}
