#include "rsa_encrypt.h"
#include "utils.h"
#include "json.hpp"
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <iostream>

typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor RSAES_OAEP_SHA256_Encryptor;
typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Decryptor RSAES_OAEP_SHA256_Decryptor;

using json = nlohmann::json;
using namespace CryptoPP;

namespace RSA_Encrypt {

    void EncryptFile(const std::string& inFile, const std::string& pubFile, const std::string& outFile, const std::string& label) {
        AutoSeededRandomPool rng;
        RSA::PublicKey publicKey = Utils::LoadPublicKey(pubFile);

        if (!publicKey.Validate(rng, 3)) {
            throw std::runtime_error("Public key validation failed");
        }

        std::string plaintext = Utils::ReadBinaryFile(inFile);
        RSAES_OAEP_SHA256_Encryptor encryptor(publicKey);
        size_t maxPlaintextLength = encryptor.FixedMaxPlaintextLength();

        if (plaintext.length() <= maxPlaintextLength) {
            std::cout << "Message size " << plaintext.length() << " bytes is within RSA limit (" << maxPlaintextLength << " bytes). Using Direct RSA-OAEP encryption.\n";
            std::string ciphertext;
            size_t c_len = encryptor.CiphertextLength(plaintext.size());
            ciphertext.resize(c_len);
            
            if (label.empty()) {
                encryptor.Encrypt(rng, reinterpret_cast<const byte*>(plaintext.data()), plaintext.size(), reinterpret_cast<byte*>(ciphertext.data()));
            } else {
                AlgorithmParameters params = MakeParameters("EncodingParameters", ConstByteArrayParameter(reinterpret_cast<const byte*>(label.data()), label.size()));
                encryptor.Encrypt(rng, reinterpret_cast<const byte*>(plaintext.data()), plaintext.size(), reinterpret_cast<byte*>(ciphertext.data()), params);
            }
            
            Utils::WriteBinaryFile(outFile, ciphertext);
            std::cout << "Saved RSA ciphertext to " << outFile << "\n";
        } else {
            std::cout << "Message size " << plaintext.length() << " bytes exceeds RSA limit (" << maxPlaintextLength << " bytes). Switching to Hybrid Envelope Encryption (AES-GCM + RSA).\n";
            
            // AES-GCM variables
            byte aesKey[32]; // 256-bit AES
            byte iv[12];     // 96-bit IV
            rng.GenerateBlock(aesKey, sizeof(aesKey));
            rng.GenerateBlock(iv, sizeof(iv));

            // Encrypt Data with AES-GCM
            GCM<AES>::Encryption gcm;
            gcm.SetKeyWithIV(aesKey, sizeof(aesKey), iv, sizeof(iv));

            std::string ciphertext, mac;
            const int TAG_SIZE = 16;
            AuthenticatedEncryptionFilter ef(gcm, new StringSink(ciphertext), false, TAG_SIZE);
            ef.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(plaintext.data()), plaintext.size());
            ef.ChannelMessageEnd(DEFAULT_CHANNEL);

            // Extract MAC from end of ciphertext
            mac = ciphertext.substr(ciphertext.size() - TAG_SIZE);
            ciphertext.resize(ciphertext.size() - TAG_SIZE);

            // Encrypt AES key with RSA
            std::string encryptedAesKey;
            StringSource ss(aesKey, sizeof(aesKey), true, new PK_EncryptorFilter(rng, encryptor, new StringSink(encryptedAesKey)));

            // Save JSON Envelope
            json envelope = {
                {"mode", "RSA-OAEP-AES-GCM"},
                {"rsa_modulus", publicKey.GetModulus().BitCount()},
                {"hash", "SHA-256"},
                {"wrapped_key", Utils::Base64Encode(encryptedAesKey)},
                {"iv", Utils::Base64Encode(std::string(reinterpret_cast<char*>(iv), sizeof(iv)))},
                {"tag", Utils::Base64Encode(mac)}
            };
            
            // We write the JSON envelope to a metadata file, or maybe we prepend it to the ciphertext file?
            // The requirement says "Output structured envelope ... Ciphertext: raw / hex / base64 ... Envelope header: JSON"
            // Let's save the JSON envelope to outFile + ".json" and ciphertext to outFile
            std::string envelopeFile = outFile + ".json";
            Utils::SaveFile(envelopeFile, envelope.dump(4));
            Utils::WriteBinaryFile(outFile, ciphertext);
            
            std::cout << "Saved AES-GCM ciphertext to " << outFile << "\n";
            std::cout << "Saved JSON Envelope to " << envelopeFile << "\n";
        }
    }
}
