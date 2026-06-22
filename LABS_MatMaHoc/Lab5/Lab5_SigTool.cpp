#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <iomanip>

// Crypto++ Includes
#include "cryptlib.h"
#include "eccrypto.h"
#include "osrng.h"
#include "oids.h"
#include "files.h"
#include "hex.h"
#include "base64.h"
#include "rsa.h"
#include "pssr.h"
#include "sha.h"
// No pem.h in standard Crypto++


using namespace CryptoPP;

// Helpers
void PrintUsage() {
    std::cout << "Usage:\n";
    std::cout << "  sigtool keygen --algo <ecdsa-p256|ecdsa-p384|rsa-pss-3072> --pub <pub.pem> --priv <priv.pem>\n";
    std::cout << "  sigtool sign --algo <ecdsa-p256|ecdsa-p384|rsa-pss-3072> --in <msg.bin> --out <sig.bin> --hash <sha256|sha384> --priv <priv.pem> [--encode <raw|der|base64>]\n";
    std::cout << "  sigtool verify --algo <ecdsa-p256|ecdsa-p384|rsa-pss-3072> --in <msg.bin> --sig <sig.bin> --pub <pub.pem> --hash <sha256|sha384> [--encode <raw|der|base64>]\n";
}

std::string ReadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open file: " + filename);
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void WriteFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open file for writing: " + filename);
    file.write(data.data(), data.size());
}

// -------------------------------------------------------------------------
// ECDSA Helpers
// -------------------------------------------------------------------------
// Save Key in PEM format
template <class Key>
void SaveKey(const std::string& filename, const Key& key, const std::string& header) {
    std::string der;
    StringSink sink(der);
    key.Save(sink);

    std::string pem;
    StringSource ss(der, true,
        new Base64Encoder(
            new StringSink(pem),
            true, // insert line breaks
            64
        )
    );

    std::ofstream file(filename);
    file << "-----BEGIN " << header << "-----\n";
    file << pem;
    file << "-----END " << header << "-----\n";
}

// Load Key from PEM format
template <class Key>
void LoadKey(const std::string& filename, Key& key, const std::string& header) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open key file");
    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (content.find("-----BEGIN") != std::string::npos) {
        std::istringstream iss(content);
        std::string line, pem;
        bool reading = false;
        while (std::getline(iss, line)) {
            if (line.find("-----BEGIN " + header + "-----") != std::string::npos) {
                reading = true;
                continue;
            }
            if (line.find("-----END " + header + "-----") != std::string::npos) {
                break;
            }
            if (reading) {
                // remove carriage returns if any
                line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
                pem += line;
            }
        }
        std::string der;
        StringSource ss(pem, true, new Base64Decoder(new StringSink(der)));
        StringSource ss2(der, true);
        key.Load(ss2);
    } else {
        // Fallback to RAW DER
        StringSource ss(content, true);
        key.Load(ss);
    }
}

template <class Curve>
void GenerateECDSA(const std::string& privFile, const std::string& pubFile, const OID& oid) {
    AutoSeededRandomPool prng;
    typename ECDSA<Curve, SHA256>::PrivateKey privKey;
    privKey.Initialize(prng, oid);

    typename ECDSA<Curve, SHA256>::PublicKey pubKey;
    privKey.MakePublicKey(pubKey);

    SaveKey(privFile, privKey, "EC PRIVATE KEY");
    SaveKey(pubFile, pubKey, "PUBLIC KEY");
    
    std::cout << "ECDSA key pair generated successfully.\n";
}

template <class Hash>
std::string SignECDSA_Deterministic(const std::string& privFile, const std::string& message) {
    typename ECDSA<ECP, Hash>::PrivateKey privKey;
    LoadKey(privFile, privKey, "EC PRIVATE KEY");

    // RFC6979 Deterministic Signature
    typename ECDSA_RFC6979<ECP, Hash>::Signer signer(privKey);
    std::string signature;

    StringSource ss(message, true, 
        new SignerFilter(NullRNG(), signer,
            new StringSink(signature)
        )
    );
    return signature;
}

template <class Hash>
bool VerifyECDSA(const std::string& pubFile, const std::string& message, const std::string& signature) {
    typename ECDSA<ECP, Hash>::PublicKey pubKey;
    LoadKey(pubFile, pubKey, "PUBLIC KEY");

    typename ECDSA_RFC6979<ECP, Hash>::Verifier verifier(pubKey);
    bool result = false;
    StringSource ss(message + signature, true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&result, sizeof(result)),
            SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_END
        )
    );
    return result;
}


// -------------------------------------------------------------------------
// RSA-PSS Helpers
// -------------------------------------------------------------------------
void GenerateRSAPSS(int keySize, const std::string& privFile, const std::string& pubFile) {
    AutoSeededRandomPool prng;
    RSA::PrivateKey privKey;
    privKey.GenerateRandomWithKeySize(prng, keySize);

    RSA::PublicKey pubKey(privKey);

    SaveKey(privFile, privKey, "RSA PRIVATE KEY");
    SaveKey(pubFile, pubKey, "PUBLIC KEY");
    
    std::cout << "RSA-PSS key pair generated successfully.\n";
}

template <class Hash>
std::string SignRSAPSS(const std::string& privFile, const std::string& message) {
    RSA::PrivateKey privKey;
    LoadKey(privFile, privKey, "RSA PRIVATE KEY");

    AutoSeededRandomPool prng;
    typename RSASS<PSS, Hash>::Signer signer(privKey);
    std::string signature;

    StringSource ss(message, true, 
        new SignerFilter(prng, signer,
            new StringSink(signature)
        )
    );
    return signature;
}

template <class Hash>
bool VerifyRSAPSS(const std::string& pubFile, const std::string& message, const std::string& signature) {
    RSA::PublicKey pubKey;
    LoadKey(pubFile, pubKey, "PUBLIC KEY");

    typename RSASS<PSS, Hash>::Verifier verifier(pubKey);
    bool result = false;
    StringSource ss(message + signature, true,
        new SignatureVerificationFilter(verifier,
            new ArraySink((byte*)&result, sizeof(result)),
            SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_END
        )
    );
    return result;
}

// -------------------------------------------------------------------------
// Encoding & Format Helpers
// -------------------------------------------------------------------------
std::string EncodeString(const std::string& data, const std::string& encodeFormat) {
    if (encodeFormat == "raw" || encodeFormat == "der") return data;
    if (encodeFormat == "base64") {
        std::string encoded;
        StringSource ss(data, true, new Base64Encoder(new StringSink(encoded), false));
        return encoded;
    }
    if (encodeFormat == "hex") {
        std::string encoded;
        StringSource ss(data, true, new HexEncoder(new StringSink(encoded)));
        return encoded;
    }
    throw std::runtime_error("Unknown encoding: " + encodeFormat);
}

std::string DecodeString(const std::string& data, const std::string& encodeFormat) {
    if (encodeFormat == "raw" || encodeFormat == "der") return data;
    if (encodeFormat == "base64") {
        std::string decoded;
        StringSource ss(data, true, new Base64Decoder(new StringSink(decoded)));
        return decoded;
    }
    if (encodeFormat == "hex") {
        std::string decoded;
        StringSource ss(data, true, new HexDecoder(new StringSink(decoded)));
        return decoded;
    }
    throw std::runtime_error("Unknown encoding: " + encodeFormat);
}

// -------------------------------------------------------------------------
// Main Routine
// -------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string command = argv[1];
    std::string algo = "ecdsa-p256", pubFile = "", privFile = "", inFile = "", outFile = "", sigFile = "", hashAlgo = "sha256", encodeFormat = "raw", batchFile = "";

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--algo" && i + 1 < argc) algo = argv[++i];
        else if (arg == "--pub" && i + 1 < argc) pubFile = argv[++i];
        else if (arg == "--priv" && i + 1 < argc) privFile = argv[++i];
        else if (arg == "--in" && i + 1 < argc) inFile = argv[++i];
        else if (arg == "--out" && i + 1 < argc) outFile = argv[++i];
        else if (arg == "--sig" && i + 1 < argc) sigFile = argv[++i];
        else if (arg == "--hash" && i + 1 < argc) hashAlgo = argv[++i];
        else if (arg == "--encode" && i + 1 < argc) encodeFormat = argv[++i];
        else if (arg == "--batch" && i + 1 < argc) batchFile = argv[++i];
    }

    try {
        if (command == "keygen") {
            if (algo == "ecdsa-p256") GenerateECDSA<ECP>(privFile, pubFile, ASN1::secp256r1());
            else if (algo == "ecdsa-p384") GenerateECDSA<ECP>(privFile, pubFile, ASN1::secp384r1());
            else if (algo == "rsa-pss-3072") GenerateRSAPSS(3072, privFile, pubFile);
            else throw std::runtime_error("Unsupported algorithm: " + algo);
        }
        else if (command == "sign") {
            std::string message = ReadFile(inFile);
            std::string rawSig;
            if (algo == "ecdsa-p256") {
                if (hashAlgo == "sha256") rawSig = SignECDSA_Deterministic<SHA256>(privFile, message);
                else if (hashAlgo == "sha384") rawSig = SignECDSA_Deterministic<SHA384>(privFile, message);
                else throw std::runtime_error("Hash mismatch or unsupported.");
            } else if (algo == "ecdsa-p384") {
                if (hashAlgo == "sha384") rawSig = SignECDSA_Deterministic<SHA384>(privFile, message);
                else if (hashAlgo == "sha256") rawSig = SignECDSA_Deterministic<SHA256>(privFile, message);
                else throw std::runtime_error("Hash mismatch or unsupported.");
            } else if (algo == "rsa-pss-3072") {
                if (hashAlgo == "sha256") rawSig = SignRSAPSS<SHA256>(privFile, message);
                else if (hashAlgo == "sha384") rawSig = SignRSAPSS<SHA384>(privFile, message);
                else throw std::runtime_error("Hash mismatch or unsupported.");
            } else {
                throw std::runtime_error("Unsupported algorithm: " + algo);
            }
            std::string encodedSig = EncodeString(rawSig, encodeFormat);
            WriteFile(outFile, encodedSig);
            std::cout << "Signature successfully generated and written to " << outFile << "\n";
        }
        else if (command == "verify") {
            auto verifySingle = [&](const std::string& msgPath, const std::string& sigPath) -> bool {
                std::string message = ReadFile(msgPath);
                std::string encodedSig = ReadFile(sigPath);
                std::string rawSig = DecodeString(encodedSig, encodeFormat);
                bool isValid = false;

                if (algo == "ecdsa-p256") {
                    if (hashAlgo == "sha256") isValid = VerifyECDSA<SHA256>(pubFile, message, rawSig);
                    else if (hashAlgo == "sha384") isValid = VerifyECDSA<SHA384>(pubFile, message, rawSig);
                } else if (algo == "ecdsa-p384") {
                    if (hashAlgo == "sha384") isValid = VerifyECDSA<SHA384>(pubFile, message, rawSig);
                    else if (hashAlgo == "sha256") isValid = VerifyECDSA<SHA256>(pubFile, message, rawSig);
                } else if (algo == "rsa-pss-3072") {
                    if (hashAlgo == "sha256") isValid = VerifyRSAPSS<SHA256>(pubFile, message, rawSig);
                    else if (hashAlgo == "sha384") isValid = VerifyRSAPSS<SHA384>(pubFile, message, rawSig);
                } else {
                    throw std::runtime_error("Unsupported algorithm: " + algo);
                }
                return isValid;
            };

            if (!batchFile.empty()) {
                std::ifstream bfile(batchFile);
                if (!bfile) throw std::runtime_error("Cannot open batch file");
                std::string line;
                int count = 0, passed = 0;
                while (std::getline(bfile, line)) {
                    if (line.empty()) continue;
                    std::istringstream iss(line);
                    std::string mFile, sFile;
                    if (iss >> mFile >> sFile) {
                        count++;
                        try {
                            if (verifySingle(mFile, sFile)) {
                                std::cout << "[PASS] " << mFile << " " << sFile << "\n";
                                passed++;
                            } else {
                                std::cout << "[FAIL] " << mFile << " " << sFile << "\n";
                            }
                        } catch(const std::exception& e) {
                            std::cout << "[ERROR] " << mFile << " " << sFile << " - " << e.what() << "\n";
                        }
                    }
                }
                std::cout << "Batch Verification: " << passed << "/" << count << " passed.\n";
                if (passed == count && count > 0) return 0;
                return 1;
            } else {
                bool isValid = verifySingle(inFile, sigFile);
                if (isValid) {
                    std::cout << "[PASS] Signature Verification Successful.\n";
                    return 0;
                } else {
                    std::cerr << "[FAIL] Signature Verification Failed.\n";
                    return 1;
                }
            }
        }
        else {
            std::cerr << "Unknown command: " << command << "\n";
            PrintUsage();
            return 1;
        }
    } catch (const Exception& e) {
        std::cerr << "Crypto++ Error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
