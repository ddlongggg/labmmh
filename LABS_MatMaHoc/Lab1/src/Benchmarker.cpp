#include "Benchmarker.h"
#include "CipherCore.h"
#include "AESUtils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <map>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/modes.h>
#include <cryptopp/xts.h>
#include <cryptopp/filters.h>

using namespace std;
using namespace CryptoPP;

namespace Benchmarker {

    template<class ENC_MODE, class DEC_MODE>
    void RunBenchForMode(ENC_MODE& enc, DEC_MODE& dec, const string& payload, const CipherCore::CipherOptions& opt, int runs, vector<double>& timings_enc, vector<double>& timings_dec) {
        string cipher;
        int operations = 1000;
        
        // 1. Warm-up (1-2 seconds) ENCRYPT
        auto warm_start = chrono::high_resolution_clock::now();
        while (true) {
            cipher.clear();
            StringSource ss(payload, true,
                new StreamTransformationFilter(enc,
                    new StringSink(cipher),
                    opt.noPadding ? StreamTransformationFilter::NO_PADDING : StreamTransformationFilter::DEFAULT_PADDING
                )
            );
            auto now = chrono::high_resolution_clock::now();
            chrono::duration<double> diff = now - warm_start;
            if (diff.count() >= 1.0) break;
        }

        // 2. Bench ENCRYPT
        for (int r = 0; r < runs; ++r) {
            auto start = chrono::high_resolution_clock::now();
            for(int i = 0; i < operations; ++i) {
                cipher.clear();
                StringSource ss(payload, true,
                    new StreamTransformationFilter(enc,
                        new StringSink(cipher),
                        opt.noPadding ? StreamTransformationFilter::NO_PADDING : StreamTransformationFilter::DEFAULT_PADDING
                    )
                );
            }
            auto end = chrono::high_resolution_clock::now();
            chrono::duration<double> diff = end - start;
            timings_enc.push_back(diff.count());
        }

        string plaintext;
        // 3. Warm-up (1-2 seconds) DECRYPT
        warm_start = chrono::high_resolution_clock::now();
        while (true) {
            plaintext.clear();
            StringSource ss(cipher, true,
                new StreamTransformationFilter(dec,
                    new StringSink(plaintext),
                    opt.noPadding ? StreamTransformationFilter::NO_PADDING : StreamTransformationFilter::DEFAULT_PADDING
                )
            );
            auto now = chrono::high_resolution_clock::now();
            chrono::duration<double> diff = now - warm_start;
            if (diff.count() >= 1.0) break;
        }

        // 4. Bench DECRYPT
        for (int r = 0; r < runs; ++r) {
            auto start = chrono::high_resolution_clock::now();
            for(int i = 0; i < operations; ++i) {
                plaintext.clear();
                StringSource ss(cipher, true,
                    new StreamTransformationFilter(dec,
                        new StringSink(plaintext),
                        opt.noPadding ? StreamTransformationFilter::NO_PADDING : StreamTransformationFilter::DEFAULT_PADDING
                    )
                );
            }
            auto end = chrono::high_resolution_clock::now();
            chrono::duration<double> diff = end - start;
            timings_dec.push_back(diff.count());
        }
    }

    template<class AEAD_ENC, class AEAD_DEC>
    void RunBenchForAead(const string& payload, const CipherCore::CipherOptions& opt, int runs, vector<double>& timings_enc, vector<double>& timings_dec) {
        string cipher;
        int operations = 1000;
        
        // 1. Warm-up ENCRYPT
        auto warm_start = chrono::high_resolution_clock::now();
        while (true) {
            AEAD_ENC enc;
            enc.SetKeyWithIV(opt.key, opt.key.size(), opt.iv, opt.iv.size());
            enc.SpecifyDataLengths(0, payload.size(), 0);
            
            cipher.clear();
            AuthenticatedEncryptionFilter ef(enc, new StringSink(cipher), false, 16);
            StringSource ss(payload, true, new Redirector(ef));
            
            auto now = chrono::high_resolution_clock::now();
            chrono::duration<double> diff = now - warm_start;
            if (diff.count() >= 1.0) break;
        }

        // 2. Bench ENCRYPT
        for (int r = 0; r < runs; ++r) {
            auto start = chrono::high_resolution_clock::now();
            for(int i = 0; i < operations; ++i) {
                AEAD_ENC enc;
                enc.SetKeyWithIV(opt.key, opt.key.size(), opt.iv, opt.iv.size());
                enc.SpecifyDataLengths(0, payload.size(), 0);

                cipher.clear();
                AuthenticatedEncryptionFilter ef(enc, new StringSink(cipher), false, 16);
                StringSource ss(payload, true, new Redirector(ef));
            }
            auto end = chrono::high_resolution_clock::now();
            chrono::duration<double> diff = end - start;
            timings_enc.push_back(diff.count());
        }

        string plaintext;
        // 3. Warm-up DECRYPT
        warm_start = chrono::high_resolution_clock::now();
        while (true) {
            AEAD_DEC dec;
            dec.SetKeyWithIV(opt.key, opt.key.size(), opt.iv, opt.iv.size());
            dec.SpecifyDataLengths(0, payload.size(), 0);
            
            plaintext.clear();
            AuthenticatedDecryptionFilter df(dec, new StringSink(plaintext), AuthenticatedDecryptionFilter::DEFAULT_FLAGS, 16);
            StringSource ss(cipher, true, new Redirector(df));
            
            auto now = chrono::high_resolution_clock::now();
            chrono::duration<double> diff = now - warm_start;
            if (diff.count() >= 1.0) break;
        }

        // 4. Bench DECRYPT
        for (int r = 0; r < runs; ++r) {
            auto start = chrono::high_resolution_clock::now();
            for(int i = 0; i < operations; ++i) {
                AEAD_DEC dec;
                dec.SetKeyWithIV(opt.key, opt.key.size(), opt.iv, opt.iv.size());
                dec.SpecifyDataLengths(0, payload.size(), 0);

                plaintext.clear();
                AuthenticatedDecryptionFilter df(dec, new StringSink(plaintext), AuthenticatedDecryptionFilter::DEFAULT_FLAGS, 16);
                StringSource ss(cipher, true, new Redirector(df));
            }
            auto end = chrono::high_resolution_clock::now();
            chrono::duration<double> diff = end - start;
            timings_dec.push_back(diff.count());
        }
    }

    void RunBenchmark(const string& inFile, const string& csvOutFile, int runs) {
        vector<string> modes = {"ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "ccm", "xts"};
        map<string, vector<double>> results_enc;
        map<string, vector<double>> results_dec;

        // Load payload into memory
        string payload;
        ifstream f(inFile, ios::binary | ios::ate);
        if(!f) throw runtime_error("Cannot open payload file");
        size_t size = f.tellg();
        f.seekg(0);
        payload.resize(size);
        f.read(&payload[0], size);
        f.close();

        for (const string& mode : modes) {
            CipherCore::CipherOptions opt;
            opt.mode = mode;
            opt.allowEcb = true; 
            opt.noPadding = (size % 16 == 0); // No padding for block sizes that fit perfectly
            
            if (mode == "gcm" || mode == "ccm") {
                opt.isAead = true;
                AESUtils::GenerateAESKey(opt.key, opt.iv, 32); 
                opt.iv.CleanNew(12);
            } else if (mode == "xts") {
                opt.isAead = false;
                AESUtils::GenerateAESKey(opt.key, opt.iv, 32);
                opt.iv.CleanNew(16);
            } else {
                opt.isAead = false;
                AESUtils::GenerateAESKey(opt.key, opt.iv, 32);
                opt.iv.CleanNew(16);
            }

            cout << "Benchmarking " << mode << " (" << runs << " runs of 1000 ops)...\n";
            try {
                if(mode == "ecb") { ECB_Mode<AES>::Encryption enc(opt.key, opt.key.size()); ECB_Mode<AES>::Decryption dec(opt.key, opt.key.size()); RunBenchForMode(enc, dec, payload, opt, runs, results_enc[mode], results_dec[mode]); }
                else if(mode == "cbc") { CBC_Mode<AES>::Encryption enc(opt.key, opt.key.size(), opt.iv); CBC_Mode<AES>::Decryption dec(opt.key, opt.key.size(), opt.iv); RunBenchForMode(enc, dec, payload, opt, runs, results_enc[mode], results_dec[mode]); }
                else if(mode == "cfb") { CFB_Mode<AES>::Encryption enc(opt.key, opt.key.size(), opt.iv); CFB_Mode<AES>::Decryption dec(opt.key, opt.key.size(), opt.iv); RunBenchForMode(enc, dec, payload, opt, runs, results_enc[mode], results_dec[mode]); }
                else if(mode == "ofb") { OFB_Mode<AES>::Encryption enc(opt.key, opt.key.size(), opt.iv); OFB_Mode<AES>::Decryption dec(opt.key, opt.key.size(), opt.iv); RunBenchForMode(enc, dec, payload, opt, runs, results_enc[mode], results_dec[mode]); }
                else if(mode == "ctr") { CTR_Mode<AES>::Encryption enc(opt.key, opt.key.size(), opt.iv); CTR_Mode<AES>::Decryption dec(opt.key, opt.key.size(), opt.iv); RunBenchForMode(enc, dec, payload, opt, runs, results_enc[mode], results_dec[mode]); }
                else if(mode == "xts") { XTS_Mode<AES>::Encryption enc(opt.key, opt.key.size(), opt.iv); XTS_Mode<AES>::Decryption dec(opt.key, opt.key.size(), opt.iv); RunBenchForMode(enc, dec, payload, opt, runs, results_enc[mode], results_dec[mode]); }
                else if(mode == "gcm") { RunBenchForAead<GCM<AES>::Encryption, GCM<AES>::Decryption>(payload, opt, runs, results_enc[mode], results_dec[mode]); }
                else if(mode == "ccm") { RunBenchForAead<CCM<AES>::Encryption, CCM<AES>::Decryption>(payload, opt, runs, results_enc[mode], results_dec[mode]); }
            } catch (const exception& e) {
                cerr << "Benchmark Error in " << mode << ": " << e.what() << endl;
                results_enc[mode] = vector<double>(runs, 0.0);
                results_dec[mode] = vector<double>(runs, 0.0);
            }
        }

        // Write CSV
        string baseName = csvOutFile;
        if (baseName.size() >= 4 && baseName.substr(baseName.size()-4) == ".csv") {
            baseName = baseName.substr(0, baseName.size()-4);
        }
        string encFile = baseName + "_enc.csv";
        string decFile = baseName + "_dec.csv";

        // Write Encrypt CSV
        ofstream csvEnc(encFile);
        csvEnc << "Run";
        for (const string& mode : modes) csvEnc << "," << mode;
        csvEnc << "\n";

        for (int i = 0; i < runs; ++i) {
            csvEnc << i;
            for (const string& mode : modes) {
                csvEnc << "," << results_enc[mode][i];
            }
            csvEnc << "\n";
        }
        
        // Write Decrypt CSV
        ofstream csvDec(decFile);
        csvDec << "Run";
        for (const string& mode : modes) csvDec << "," << mode;
        csvDec << "\n";

        for (int i = 0; i < runs; ++i) {
            csvDec << i;
            for (const string& mode : modes) {
                csvDec << "," << results_dec[mode][i];
            }
            csvDec << "\n";
        }
        
        cout << "Benchmark complete. Saved to " << encFile << " and " << decFile << endl;
    }
}
