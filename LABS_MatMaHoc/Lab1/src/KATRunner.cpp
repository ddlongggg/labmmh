#include "KATRunner.h"
#include "CipherCore.h"
#include "json.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <cryptopp/hex.h>

using namespace std;
using namespace CryptoPP;
using json = nlohmann::json;

namespace KATRunner {

    SecByteBlock ParseHex(const string& hexStr) {
        SecByteBlock output(hexStr.size() / 2);
        StringSource ss(hexStr, true, new HexDecoder(new ArraySink(output, output.size())));
        return output;
    }

    string EncodeHex(const SecByteBlock& block) {
        string hexStr;
        StringSource ss(block, block.size(), true, new HexEncoder(new StringSink(hexStr), false));
        return hexStr;
    }

    void RunKAT(const string& vectorsJsonFile) {
        ifstream inFile(vectorsJsonFile);
        if (!inFile) {
            cerr << "Could not open " << vectorsJsonFile << endl;
            return;
        }

        json j;
        inFile >> j;

        int passCount = 0;
        int failCount = 0;

        for (const auto& test : j["test_cases"]) {
            string name = test["name"];
            CipherCore::CipherOptions opt;
            opt.mode = test["mode"];
            opt.key = ParseHex(test["key"]);
            opt.iv = ParseHex(test["iv"]);
            opt.isAead = test["is_aead"];
            opt.noPadding = true;
            
            if (test.contains("aad")) {
                SecByteBlock aadBlock = ParseHex(test["aad"]);
                opt.aad = string((const char*)aadBlock.data(), aadBlock.size());
            }

            SecByteBlock pt = ParseHex(test["pt"]);
            SecByteBlock expectedCt = ParseHex(test["ct"]);
            SecByteBlock expectedTag;
            if (opt.isAead && test.contains("tag")) {
                expectedTag = ParseHex(test["tag"]);
            }

            // Write PT to temp file
            {
                ofstream ptFile("kat_temp_pt.bin", ios::binary);
                ptFile.write((const char*)pt.data(), pt.size());
            }

            bool passed = true;
            try {
                if (opt.mode == "gcm") {
                    cout << "DEBUG: key size=" << opt.key.size() << " iv size=" << opt.iv.size() << endl;
                }
                SecByteBlock outTag;
                CipherCore::Encrypt("kat_temp_pt.bin", "kat_temp_ct.bin", opt, outTag);

                // Read CT
                ifstream ctFile("kat_temp_ct.bin", ios::binary | ios::ate);
                size_t ctSize = ctFile.tellg();
                ctFile.seekg(0);
                SecByteBlock actualCt(ctSize);
                ctFile.read((char*)actualCt.data(), ctSize);

                if (actualCt != expectedCt) {
                    passed = false;
                    cout << "[FAIL] " << name << " - Ciphertext mismatch\n";
                    cout << "Expected: " << EncodeHex(expectedCt) << "\n";
                    cout << "Actual  : " << EncodeHex(actualCt) << "\n";
                }

                if (opt.isAead && outTag != expectedTag) {
                    passed = false;
                    cout << "[FAIL] " << name << " - Tag mismatch\n";
                    cout << "Expected: " << EncodeHex(expectedTag) << "\n";
                    cout << "Actual  : " << EncodeHex(outTag) << "\n";
                }

            } catch (const std::exception& e) {
                passed = false;
                cout << "[FAIL] " << name << " - Exception: " << e.what() << "\n";
            }

            if (passed) {
                cout << "[PASS] " << name << "\n";
                passCount++;
            } else {
                failCount++;
            }
        }

        cout << "--- KAT Summary ---\n";
        cout << "Passed: " << passCount << "\n";
        cout << "Failed: " << failCount << "\n";
        cout << "Total : " << passCount + failCount << "\n";
    }
}
