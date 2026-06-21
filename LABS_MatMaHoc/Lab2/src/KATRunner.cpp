#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include "json.hpp"
#include "AESCore.h"
#include "AES_CTR.h"

using json = nlohmann::json;
using namespace std;

namespace KATRunner {

    uint8_t HexCharToByte(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    }

    vector<uint8_t> ParseHex(const string& hex) {
        vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            bytes.push_back((HexCharToByte(hex[i]) << 4) | HexCharToByte(hex[i+1]));
        }
        return bytes;
    }

    void RunKAT(const string& katFile) {
        ifstream f(katFile);
        if (!f) {
            cerr << "Could not open KAT file: " << katFile << endl;
            return;
        }

        json vectors;
        f >> vectors;

        int passed = 0;
        int failed = 0;

        for (const auto& test : vectors["test_cases"]) {
            string name = test["name"];
            string mode = test["mode"];
            vector<uint8_t> key = ParseHex(test["key"]);
            vector<uint8_t> pt = ParseHex(test["plaintext"]);
            vector<uint8_t> expected_ct = ParseHex(test["ciphertext"]);

            vector<uint8_t> out_ct(pt.size());

            if (mode == "ecb") { 
                AESCore::AES aes(key.data(), key.size());
                if (pt.size() == 16) {
                    aes.EncryptBlock(pt.data(), out_ct.data());
                } else {
                    cerr << "ECB test must have exactly 16 bytes. Skipping " << name << endl;
                    continue;
                }
            } else if (mode == "ctr") {
                vector<uint8_t> iv = ParseHex(test["iv"]);
                AESCore::AES aes(key.data(), key.size());
                AES_CTR::ProcessBuffer(aes, iv.data(), pt.data(), out_ct.data(), pt.size());
            } else {
                cerr << "Unsupported mode " << mode << " in KAT. Skipping " << name << endl;
                continue;
            }

            bool match = true;
            for(size_t i=0; i<expected_ct.size(); i++) {
                if (out_ct[i] != expected_ct[i]) { match = false; break; }
            }

            if (match) {
                cout << "[PASS] " << name << endl;
                passed++;
            } else {
                cout << "[FAIL] " << name << endl;
                failed++;
            }
        }

        cout << "--- KAT Summary ---\n";
        cout << "Passed: " << passed << "\n";
        cout << "Failed: " << failed << "\n";
        cout << "Total : " << passed + failed << "\n";
    }

}
