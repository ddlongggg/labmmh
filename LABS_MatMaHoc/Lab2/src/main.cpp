#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <random>
#include <iomanip>
#include "AESCore.h"
#include "AES_CTR.h"
#include "AES_XTS.h"
#include "Benchmarker.h"

namespace KATRunner {
    void RunKAT(const std::string& katFile);
}

using namespace std;

void PrintUsage() {
    cout << "Usage: aestool2 <command> [options]\n";
    cout << "Commands:\n";
    cout << "  generate --key KEYFILE [--iv IVFILE] [--size 16|24|32|64]\n";
    cout << "  encrypt  --mode ctr|xts --key KEYFILE --iv IVFILE --in INFILE --out OUTFILE\n";
    cout << "  decrypt  --mode ctr|xts --key KEYFILE --iv IVFILE --in INFILE --out OUTFILE\n";
    cout << "  kat      --kat vectors.json\n";
    cout << "  bench    --in INFILE --out OUTCSV [--runs NUM]\n";
}

vector<uint8_t> ReadFile(const string& filename) {
    ifstream f(filename, ios::binary | ios::ate);
    if (!f) throw runtime_error("Failed to open file: " + filename);
    size_t size = f.tellg();
    f.seekg(0);
    vector<uint8_t> buf(size);
    f.read((char*)buf.data(), size);
    return buf;
}

void WriteFile(const string& filename, const vector<uint8_t>& buf) {
    ofstream f(filename, ios::binary);
    if (!f) throw runtime_error("Failed to write to file: " + filename);
    f.write((const char*)buf.data(), buf.size());
}

string GetCmdOption(char** begin, char** end, const string& option) {
    char** itr = find(begin, end, option);
    if (itr != end && ++itr != end) {
        return *itr;
    }
    return "";
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        PrintUsage();
        return 1;
    }

    string cmd = argv[1];

    try {
        if (cmd == "kat") {
            string katFile = GetCmdOption(argv, argv + argc, "--kat");
            if(katFile.empty()) throw runtime_error("Missing --kat file path");
            KATRunner::RunKAT(katFile);
        }
        else if (cmd == "generate") {
            string keyFile = GetCmdOption(argv, argv + argc, "--key");
            string ivFile = GetCmdOption(argv, argv + argc, "--iv");
            string sizeStr = GetCmdOption(argv, argv + argc, "--size");
            
            int size = 16;
            if (!sizeStr.empty()) size = stoi(sizeStr);
            if (size != 16 && size != 24 && size != 32 && size != 48 && size != 64) throw runtime_error("Invalid key size");

            random_device rd;
            
            if (!keyFile.empty()) {
                vector<uint8_t> key(size);
                for(int i=0; i<size; i++) key[i] = rd() & 0xFF;
                WriteFile(keyFile, key);
                cout << "Generated " << size << "-byte key at " << keyFile << endl;
            }
            if (!ivFile.empty()) {
                vector<uint8_t> iv(16);
                for(int i=0; i<16; i++) iv[i] = rd() & 0xFF;
                WriteFile(ivFile, iv);
                cout << "Generated 16-byte IV at " << ivFile << endl;
            }
        }
        else if (cmd == "bench") {
            string inFile = GetCmdOption(argv, argv + argc, "--in");
            string outFile = GetCmdOption(argv, argv + argc, "--out");
            int runs = 30;
            string runsStr = GetCmdOption(argv, argv + argc, "--runs");
            if (!runsStr.empty()) runs = stoi(runsStr);

            if (inFile.empty() || outFile.empty()) {
                throw runtime_error("Missing required arguments for bench.");
            }

            Benchmarker::RunBenchmark(inFile, outFile, runs);
        }
        else if (cmd == "encrypt" || cmd == "decrypt") {
            string mode = GetCmdOption(argv, argv + argc, "--mode");
            string keyFile = GetCmdOption(argv, argv + argc, "--key");
            string ivFile = GetCmdOption(argv, argv + argc, "--iv");
            string inFile = GetCmdOption(argv, argv + argc, "--in");
            string outFile = GetCmdOption(argv, argv + argc, "--out");

            if (mode != "ctr" && mode != "xts") throw runtime_error("Only --mode ctr or xts are supported.");
            if (keyFile.empty() || ivFile.empty() || inFile.empty() || outFile.empty()) {
                throw runtime_error("Missing required arguments");
            }

            vector<uint8_t> key = ReadFile(keyFile);
            vector<uint8_t> iv = ReadFile(ivFile);
            if (iv.size() != 16) {
                throw runtime_error("Invalid IV/Tweak length. Requires exactly 16 bytes.");
            }

            vector<uint8_t> input = ReadFile(inFile);
            vector<uint8_t> output(input.size());

            if (mode == "ctr") {
                if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
                    throw runtime_error("Invalid key length for CTR. Must be 16, 24, or 32 bytes.");
                }
                AESCore::AES aes(key.data(), key.size());
                AES_CTR::ProcessBuffer(aes, iv.data(), input.data(), output.data(), input.size());
            } else if (mode == "xts") {
                if (key.size() != 32 && key.size() != 48 && key.size() != 64) {
                    throw runtime_error("Invalid key length for XTS. Must be 32, 48, or 64 bytes.");
                }
                size_t halfKey = key.size() / 2;
                AESCore::AES aes1(key.data(), halfKey);
                AESCore::AES aes2(key.data() + halfKey, halfKey);
                bool isEncrypt = (cmd == "encrypt");
                AES_XTS::ProcessBuffer(aes1, aes2, iv.data(), input.data(), output.data(), input.size(), isEncrypt);
            }

            WriteFile(outFile, output);
            cout << "Operation complete. Output written to " << outFile << endl;
        } else {
            PrintUsage();
        }
    } catch(const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
