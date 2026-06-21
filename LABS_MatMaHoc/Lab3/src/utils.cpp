#include "utils.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <iostream>

#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/queue.h>

using namespace CryptoPP;

namespace Utils {

    void SaveFile(const std::string& filename, const std::string& content) {
        std::ofstream file(filename);
        if (!file.is_open()) throw std::runtime_error("Cannot open file for writing: " + filename);
        file << content;
    }

    std::string LoadFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) throw std::runtime_error("Cannot open file for reading: " + filename);
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    std::string ReadBinaryFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) throw std::runtime_error("Cannot open file for reading: " + filename);
        std::ostringstream ss;
        ss << file.rdbuf();
        return ss.str();
    }

    void WriteBinaryFile(const std::string& filename, const std::string& data) {
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) throw std::runtime_error("Cannot open file for writing: " + filename);
        file.write(data.data(), data.size());
    }

    std::string Base64Encode(const std::string& data) {
        std::string encoded;
        StringSource ss(data, true, new Base64Encoder(new StringSink(encoded), false)); // false = no newlines
        return encoded;
    }

    std::string Base64Decode(const std::string& data) {
        std::string decoded;
        StringSource ss(data, true, new Base64Decoder(new StringSink(decoded)));
        return decoded;
    }

    void SavePrivateKeyToDER(const RSA::PrivateKey& key, const std::string& filename) {
        ByteQueue queue;
        key.Save(queue);
        FileSink file(filename.c_str());
        queue.CopyTo(file);
        file.MessageEnd();
    }

    void SavePublicKeyToDER(const RSA::PublicKey& key, const std::string& filename) {
        ByteQueue queue;
        key.Save(queue);
        FileSink file(filename.c_str());
        queue.CopyTo(file);
        file.MessageEnd();
    }

    void SavePrivateKeyToPEM(const RSA::PrivateKey& key, const std::string& filename) {
        ByteQueue queue;
        key.Save(queue);
        
        std::string derData;
        StringSink ss(derData);
        queue.CopyTo(ss);
        
        std::string base64Data;
        StringSource ss2(derData, true, new Base64Encoder(new StringSink(base64Data), true, 64));
        
        std::ofstream file(filename);
        file << "-----BEGIN RSA PRIVATE KEY-----\n";
        file << base64Data;
        file << "-----END RSA PRIVATE KEY-----\n";
    }

    void SavePublicKeyToPEM(const RSA::PublicKey& key, const std::string& filename) {
        ByteQueue queue;
        key.Save(queue);
        
        std::string derData;
        StringSink ss(derData);
        queue.CopyTo(ss);
        
        std::string base64Data;
        StringSource ss2(derData, true, new Base64Encoder(new StringSink(base64Data), true, 64));
        
        std::ofstream file(filename);
        file << "-----BEGIN PUBLIC KEY-----\n";
        file << base64Data;
        file << "-----END PUBLIC KEY-----\n";
    }

    RSA::PrivateKey LoadPrivateKey(const std::string& filename) {
        RSA::PrivateKey key;
        try {
            // Try loading as PEM first
            std::string content = LoadFile(filename);
            if (content.find("-----BEGIN") != std::string::npos) {
                std::string base64Data;
                bool inKey = false;
                std::istringstream stream(content);
                std::string line;
                while (std::getline(stream, line)) {
                    if (line.find("-----BEGIN") != std::string::npos) { inKey = true; continue; }
                    if (line.find("-----END") != std::string::npos) { break; }
                    if (inKey) base64Data += line;
                }
                std::string derData = Base64Decode(base64Data);
                ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
                key.Load(as);
            } else {
                // Try as DER
                FileSource fs(filename.c_str(), true);
                key.Load(fs);
            }
        } catch (const Exception& e) {
            throw std::runtime_error("Failed to load private key: " + std::string(e.what()));
        }
        return key;
    }

    RSA::PublicKey LoadPublicKey(const std::string& filename) {
        RSA::PublicKey key;
        try {
            // Try loading as PEM first
            std::string content = LoadFile(filename);
            if (content.find("-----BEGIN") != std::string::npos) {
                std::string base64Data;
                bool inKey = false;
                std::istringstream stream(content);
                std::string line;
                while (std::getline(stream, line)) {
                    if (line.find("-----BEGIN") != std::string::npos) { inKey = true; continue; }
                    if (line.find("-----END") != std::string::npos) { break; }
                    if (inKey) base64Data += line;
                }
                std::string derData = Base64Decode(base64Data);
                ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
                key.Load(as);
            } else {
                // Try as DER
                FileSource fs(filename.c_str(), true);
                key.Load(fs);
            }
        } catch (const Exception& e) {
            throw std::runtime_error("Failed to load public key: " + std::string(e.what()));
        }
        return key;
    }
}
