#ifndef RSA_KEYGEN_H
#define RSA_KEYGEN_H

#include <string>

namespace RSA_KeyGen {
    void GenerateKeys(int bits, const std::string& pubFile, const std::string& privFile);
}

#endif // RSA_KEYGEN_H
