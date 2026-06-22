#include "rsa_decrypt.h"
#include "utils.h"
#include "json.hpp"
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <fstream>

typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor RSAES_OAEP_SHA256_Encryptor;
typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Decryptor RSAES_OAEP_SHA256_Decryptor;

using json = nlohmann::json;
using namespace CryptoPP;

namespace RSA_Decrypt {

    void DecryptFile(const std::string& inFile, const std::string& privFile, const std::string& outFile, const std::string& label) {
        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey = Utils::LoadPrivateKey(privFile);

        if (!privateKey.Validate(rng, 3)) {
            throw std::runtime_error("Private key validation failed");
        }

        RSAES_OAEP_SHA256_Decryptor decryptor(privateKey);

        // Check if there is an envelope file
        std::string envelopeFile = inFile + ".json";
        std::ifstream envStream(envelopeFile);
        
        if (envStream.good()) {
            std::cout << "Envelope " << envelopeFile << " found. Attempting Hybrid AES-GCM Decryption...\n";
            json envelope;
            try {
                envStream >> envelope;
            } catch (json::parse_error& e) {
                throw std::runtime_error("Tampered or invalid JSON envelope: " + std::string(e.what()));
            }

            if (envelope["mode"] != "RSA-OAEP-AES-GCM") {
                throw std::runtime_error("Unsupported hybrid mode: " + envelope["mode"].get<std::string>());
            }

            std::string encryptedKey = Utils::Base64Decode(envelope["wrapped_key"].get<std::string>());
            std::string iv = Utils::Base64Decode(envelope["iv"].get<std::string>());
            std::string tag = Utils::Base64Decode(envelope["tag"].get<std::string>());

            std::string aesKey;
            try {
                StringSource ss(encryptedKey, true, new PK_DecryptorFilter(rng, decryptor, new StringSink(aesKey)));
            } catch (const Exception& e) {
                throw std::runtime_error("RSA decryption of wrapped key failed. Incorrect private key or tampered wrapped key.");
            }

            if (aesKey.size() != 32) {
                throw std::runtime_error("Recovered AES key has invalid size");
            }

            std::string ciphertext = Utils::ReadBinaryFile(inFile);
            std::string plaintext;

            try {
                GCM<AES>::Decryption gcm;
                gcm.SetKeyWithIV(reinterpret_cast<const byte*>(aesKey.data()), aesKey.size(), 
                                 reinterpret_cast<const byte*>(iv.data()), iv.size());

                AuthenticatedDecryptionFilter df(gcm, new StringSink(plaintext), 
                                                 AuthenticatedDecryptionFilter::MAC_AT_BEGIN | AuthenticatedDecryptionFilter::THROW_EXCEPTION, 
                                                 tag.size());

                // For CryptoPP MAC_AT_BEGIN, we put the MAC first, then the ciphertext
                df.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(tag.data()), tag.size());
                df.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.size());
                df.ChannelMessageEnd(DEFAULT_CHANNEL);

            } catch (const HashVerificationFilter::HashVerificationFailed& e) {
                throw std::runtime_error("AES-GCM tag verification failed! The ciphertext or tag has been tampered with.");
            } catch (const Exception& e) {
                throw std::runtime_error("AES-GCM decryption failed: " + std::string(e.what()));
            }

            Utils::WriteBinaryFile(outFile, plaintext);
            std::cout << "Successfully decrypted hybrid envelope and saved plaintext to " << outFile << "\n";

        } else {
            std::cout << "No envelope found. Attempting Direct RSA-OAEP Decryption...\n";
            std::string ciphertext = Utils::ReadBinaryFile(inFile);
            std::string plaintext;
            
            try {
                size_t p_max = decryptor.MaxPlaintextLength(ciphertext.size());
                plaintext.resize(p_max);
                DecodingResult res;

                if (label.empty()) {
                    res = decryptor.Decrypt(rng, reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.size(), reinterpret_cast<byte*>(plaintext.data()));
                } else {
                    AlgorithmParameters params = MakeParameters("EncodingParameters", ConstByteArrayParameter(reinterpret_cast<const byte*>(label.data()), label.size()));
                    res = decryptor.Decrypt(rng, reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.size(), reinterpret_cast<byte*>(plaintext.data()), params);
                }
                
                if (!res.isValidCoding) {
                    throw std::runtime_error("Invalid coding");
                }
                plaintext.resize(res.messageLength);
            } catch (const Exception& e) {
                throw std::runtime_error("Direct RSA-OAEP decryption failed. Incorrect private key, label, or tampered ciphertext.");
            }

            Utils::WriteBinaryFile(outFile, plaintext);
            std::cout << "Successfully decrypted RSA ciphertext and saved plaintext to " << outFile << "\n";
        }
    }
}
