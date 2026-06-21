#include <iostream>
#include <string>
#include <vector>
#include "AESUtils.h"
#include "CipherCore.h"
#include "KATRunner.h"
#include "Benchmarker.h"
#include "json.hpp"
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <fstream>

using namespace std;
using namespace CryptoPP;

void PrintUsage() {
    cout << "Usage: aestool <command> [options]\n";
    cout << "Commands:\n";
    cout << "  generate --key KEYFILE [--format hex|bin]\n";
    cout << "  encrypt  --mode MODE --key KEYFILE [--in INFILE | --text STRING] --out OUTFILE [--iv IVFILE] [--aead] [--aad AADTEXT]\n";
    cout << "  decrypt  --mode MODE --key KEYFILE --in INFILE --out OUTFILE [--iv IVFILE] [--sidecar SIDECARJSON] [--aead] [--aad AADTEXT]\n";
    cout << "  kat      --kat vectors.json\n";
    cout << "  bench    --in INFILE --out OUTCSV [--runs NUM]\n";
    cout << "Options:\n";
    cout << "  --allow-ecb      Overrides the ECB block size restriction.\n";
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        PrintUsage();
        return 1;
    }

    string cmd = argv[1];
    if (cmd == "kat") {
        string katFile = "";
        for(int i = 2; i < argc; i++) {
            if(string(argv[i]) == "--kat" && i+1 < argc) katFile = argv[++i];
        }
        if(!katFile.empty()) KATRunner::RunKAT(katFile);
        else cout << "Missing --kat file path." << endl;
        return 0;
    }

    try {
        if (cmd == "generate") {
            string keyFile = "key.bin";
            KeyFormat format = KeyFormat::BIN;
            for(int i = 2; i < argc; i++) {
                string arg = argv[i];
                if(arg == "--key" && i+1 < argc) keyFile = argv[++i];
                if(arg == "--format" && i+1 < argc) {
                    string f = argv[++i];
                    if(f == "hex") format = KeyFormat::HEX;
                }
            }

            SecByteBlock key, iv;
            AESUtils::GenerateAESKey(key, iv);
            AESUtils::SaveKey(format, keyFile, key, iv);
            cout << "Key generated successfully to " << keyFile << endl;
        } 
        else if (cmd == "encrypt" || cmd == "decrypt") {
            CipherCore::CipherOptions opt;
            string inFile, outFile, keyFile, textInput, ivFile, sidecarFile;
            KeyFormat format = KeyFormat::BIN; // default

            for(int i = 2; i < argc; i++) {
                string arg = argv[i];
                if(arg == "--mode" && i+1 < argc) opt.mode = argv[++i];
                else if(arg == "--key" && i+1 < argc) keyFile = argv[++i];
                else if(arg == "--in" && i+1 < argc) inFile = argv[++i];
                else if(arg == "--out" && i+1 < argc) outFile = argv[++i];
                else if(arg == "--text" && i+1 < argc) textInput = argv[++i];
                else if(arg == "--iv" && i+1 < argc) ivFile = argv[++i];
                else if(arg == "--nonce" && i+1 < argc) ivFile = argv[++i];
                else if(arg == "--sidecar" && i+1 < argc) sidecarFile = argv[++i];
                else if(arg == "--aead") opt.isAead = true;
                else if(arg == "--aad" && i+1 < argc) opt.aad = argv[++i];
                else if(arg == "--allow-ecb") opt.allowEcb = true;
                else if(arg == "--format" && i+1 < argc) {
                    string f = argv[++i];
                    if(f == "hex") format = KeyFormat::HEX;
                }
            }

            if(opt.mode.empty() || keyFile.empty() || outFile.empty()) {
                throw runtime_error("Missing required arguments for encrypt/decrypt.");
            }
            if(inFile.empty() && textInput.empty()) {
                throw runtime_error("Missing input (--in or --text).");
            }

            if (!textInput.empty()) {
                inFile = "temp_text_in.txt";
                ofstream out(inFile);
                out << textInput;
            }

            // Load Key and IV
            SecByteBlock fileIv; 
            AESUtils::LoadKey(format, keyFile, opt.key, fileIv);
            opt.iv = fileIv;

            if (!ivFile.empty()) {
                string ivHex;
                ifstream in(ivFile);
                if(in) in >> ivHex;
                else ivHex = ivFile; // assume it's a direct hex string if file fails
                opt.iv.CleanNew(ivHex.size()/2);
                StringSource(ivHex, true, new HexDecoder(new ArraySink(opt.iv, opt.iv.size())));
            }

            if (cmd == "encrypt") {
                if (ivFile.empty() && opt.mode != "ecb" && opt.mode != "xts") {
                    AutoSeededRandomPool prng;
                    opt.iv.CleanNew(AES::BLOCKSIZE);
                    prng.GenerateBlock(opt.iv, opt.iv.size());
                }

                AESUtils::CheckAndRecordNonce(opt.mode, opt.key, opt.iv);

                SecByteBlock tag;
                CipherCore::Encrypt(inFile, outFile, opt, tag);
                cout << "Encryption complete." << endl;
                
                AESUtils::SaveSidecar(outFile + ".json", "AES", opt.mode, opt.iv, opt.aad, tag);
                cout << "Saved metadata to " << outFile << ".json" << endl;

                string ciphertextBase64;
                FileSource(outFile.c_str(), true, new Base64Encoder(new StringSink(ciphertextBase64), false));
                cout << "Ciphertext (Base64):\n" << ciphertextBase64 << endl;
            } else {
                SecByteBlock tag;
                if (!sidecarFile.empty()) {
                    ifstream in(sidecarFile);
                    if (in) {
                        nlohmann::json j;
                        in >> j;
                        if (j.contains("iv") && ivFile.empty()) {
                            string ivHex = j["iv"];
                            opt.iv.CleanNew(ivHex.size() / 2);
                            StringSource(ivHex, true, new HexDecoder(new ArraySink(opt.iv, opt.iv.size())));
                        }
                        if (j.contains("tag")) {
                            string tagHex = j["tag"];
                            tag.CleanNew(tagHex.size() / 2);
                            StringSource(tagHex, true, new HexDecoder(new ArraySink(tag, tag.size())));
                        }
                        if (j.contains("aad") && opt.aad.empty()) {
                            opt.aad = j["aad"];
                        }
                    }
                }
                
                CipherCore::Decrypt(inFile, outFile, opt, tag);
                cout << "Decryption complete." << endl;

                ifstream res(outFile, ios::binary | ios::ate);
                if (res.tellg() < 1000) {
                    res.seekg(0);
                    string pt((istreambuf_iterator<char>(res)), istreambuf_iterator<char>());
                    cout << "Plaintext:\n" << pt << endl;
                }
            }
        } else if (cmd == "bench") {
            string inFile, outFile;
            int runs = 30;
            for(int i = 2; i < argc; i++) {
                string arg = argv[i];
                if(arg == "--in" && i+1 < argc) inFile = argv[++i];
                else if(arg == "--out" && i+1 < argc) outFile = argv[++i];
                else if(arg == "--runs" && i+1 < argc) runs = stoi(argv[++i]);
            }

            if (inFile.empty() || outFile.empty()) {
                throw runtime_error("Missing required arguments for bench.");
            }

            Benchmarker::RunBenchmark(inFile, outFile, runs);
        } else {
            PrintUsage();
        }
    } catch(const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}
