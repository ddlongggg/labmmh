#ifndef RSA_DECRYPT_H
#define RSA_DECRYPT_H

#include <string>

namespace RSA_Decrypt {
    void DecryptFile(const std::string& inFile, const std::string& privFile, const std::string& outFile, const std::string& label = "");
}

#endif // RSA_DECRYPT_H
