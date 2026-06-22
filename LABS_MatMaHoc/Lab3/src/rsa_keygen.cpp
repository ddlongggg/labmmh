#include "rsa_keygen.h"
#include "utils.h"
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include "json.hpp"

using json = nlohmann::json;
using namespace CryptoPP;

namespace RSA_KeyGen {
    std::string GetCurrentTimeStr() {
        std::time_t now = std::time(nullptr);
        std::tm* local_time = std::localtime(&now);
        std::ostringstream oss;
        oss << std::put_time(local_time, "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    void GenerateKeys(int bits, const std::string& pubFile, const std::string& privFile) {
        if (bits < 3072) {
            std::cerr << "Warning: Modulus size " << bits << " bits is less than recommended 3072 bits.\n";
        }

        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, bits);

        RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);

        if (!privateKey.Validate(rng, 3) || !publicKey.Validate(rng, 3)) {
            throw std::runtime_error("Key validation failed");
        }

        Utils::SavePublicKeyToPEM(publicKey, pubFile);
        Utils::SavePrivateKeyToPEM(privateKey, privFile);

        std::string pubDerFile = pubFile.substr(0, pubFile.find_last_of('.')) + ".der";
        std::string privDerFile = privFile.substr(0, privFile.find_last_of('.')) + ".der";
        Utils::SavePublicKeyToDER(publicKey, pubDerFile);
        Utils::SavePrivateKeyToDER(privateKey, privDerFile);

        json metadata = {
            {"creation_time", GetCurrentTimeStr()},
            {"modulus_bits", bits},
            {"hash", "SHA-256"}
        };
        std::string metaFile = pubFile.substr(0, pubFile.find_last_of('.')) + "_metadata.json";
        Utils::SaveFile(metaFile, metadata.dump(4));

        std::cout << "Successfully generated RSA-" << bits << " key pair.\n";
        std::cout << "Saved public key: " << pubFile << " and " << pubDerFile << "\n";
        std::cout << "Saved private key: " << privFile << " and " << privDerFile << "\n";
        std::cout << "Saved metadata: " << metaFile << "\n";
    }
}
