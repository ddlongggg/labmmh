#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <cryptopp/rsa.h>

namespace Utils {

    // File I/O
    void SaveFile(const std::string& filename, const std::string& content);
    std::string LoadFile(const std::string& filename);
    std::string ReadBinaryFile(const std::string& filename);
    void WriteBinaryFile(const std::string& filename, const std::string& data);

    // Base64 & Hex
    std::string Base64Encode(const std::string& data);
    std::string Base64Decode(const std::string& data);
    std::string HexEncode(const std::string& data);
    std::string HexDecode(const std::string& data);

    // Key Conversions (DER <-> PEM)
    void SavePrivateKeyToPEM(const CryptoPP::RSA::PrivateKey& key, const std::string& filename);
    void SavePublicKeyToPEM(const CryptoPP::RSA::PublicKey& key, const std::string& filename);

    void SavePrivateKeyToDER(const CryptoPP::RSA::PrivateKey& key, const std::string& filename);
    void SavePublicKeyToDER(const CryptoPP::RSA::PublicKey& key, const std::string& filename);

    CryptoPP::RSA::PrivateKey LoadPrivateKey(const std::string& filename);
    CryptoPP::RSA::PublicKey LoadPublicKey(const std::string& filename);
}

#endif // UTILS_H
