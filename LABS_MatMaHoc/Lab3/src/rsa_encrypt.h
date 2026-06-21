#ifndef RSA_ENCRYPT_H
#define RSA_ENCRYPT_H

#include <string>

namespace RSA_Encrypt {
    void EncryptFile(const std::string& inFile, const std::string& pubFile, const std::string& outFile, const std::string& label = "");
}

#endif // RSA_ENCRYPT_H
