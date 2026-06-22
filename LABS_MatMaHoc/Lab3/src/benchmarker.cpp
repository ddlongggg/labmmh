#include "benchmarker.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <fstream>

typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Encryptor RSAES_OAEP_SHA256_Encryptor;
typedef CryptoPP::RSAES<CryptoPP::OAEP<CryptoPP::SHA256>>::Decryptor RSAES_OAEP_SHA256_Decryptor;

using namespace CryptoPP;
using namespace std::chrono;

namespace Benchmarker {

    void BenchmarkRSA(int bits) {
        AutoSeededRandomPool rng;
        std::cout << "\n--- Benchmarking RSA-" << bits << " ---\n";

        // Keygen
        auto start = high_resolution_clock::now();
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, bits);
        RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);
        auto stop = high_resolution_clock::now();
        std::cout << "Key Generation: " << duration_cast<milliseconds>(stop - start).count() << " ms\n";

        // Generate data that fits in max plaintext length
        RSAES_OAEP_SHA256_Encryptor encryptor(publicKey);
        size_t maxLen = encryptor.FixedMaxPlaintextLength();
        std::string plaintext(maxLen, 'A');
        std::string ciphertext;

        int runs = 30;
        int ops = 200;
        std::vector<double> enc_times(runs);
        std::vector<double> dec_times(runs);

        // Encryption
        std::cout << "Encryption (" << runs << " runs of " << ops << " ops)...\n";
        for (int r = 0; r < runs; ++r) {
            start = high_resolution_clock::now();
            for (int i=0; i<ops; i++) {
                ciphertext.clear();
                size_t c_len = encryptor.CiphertextLength(plaintext.size());
                ciphertext.resize(c_len);
                encryptor.Encrypt(rng, reinterpret_cast<const byte*>(plaintext.data()), plaintext.size(), reinterpret_cast<byte*>(ciphertext.data()));
            }
            stop = high_resolution_clock::now();
            enc_times[r] = duration_cast<milliseconds>(stop - start).count();
        }

        // Decryption
        RSAES_OAEP_SHA256_Decryptor decryptor(privateKey);
        std::string recovered;
        std::cout << "Decryption (" << runs << " runs of " << ops << " ops)...\n";
        for (int r = 0; r < runs; ++r) {
            start = high_resolution_clock::now();
            for (int i=0; i<ops; i++) {
                recovered.clear();
                size_t p_max = decryptor.MaxPlaintextLength(ciphertext.size());
                recovered.resize(p_max);
                DecodingResult res = decryptor.Decrypt(rng, reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.size(), reinterpret_cast<byte*>(recovered.data()));
                recovered.resize(res.messageLength);
            }
            stop = high_resolution_clock::now();
            dec_times[r] = duration_cast<milliseconds>(stop - start).count();
        }

        // Write to CSV
        std::string csvName = "rsa_" + std::to_string(bits) + "_benchmark.csv";
        std::ofstream csv(csvName);
        csv << "Run,Encrypt_ms,Decrypt_ms\n";
        for (int r = 0; r < runs; ++r) {
            csv << r << "," << enc_times[r] << "," << dec_times[r] << "\n";
        }
        std::cout << "Saved RSA-" << bits << " results to " << csvName << "\n";
    }

    void BenchmarkHybrid() {
        AutoSeededRandomPool rng;
        std::cout << "\n--- Benchmarking Hybrid Encryption (AES-GCM 256) ---\n";

        // Generate RSA key for hybrid wrapping
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, 3072);
        RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);
        RSAES_OAEP_SHA256_Encryptor rsaEncryptor(publicKey);

        // Pre-generate random payloads
        std::vector<size_t> sizes = {1024, 1024 * 1024, 100 * 1024 * 1024}; // 1KiB, 1MiB, 100MiB
        std::vector<std::string> names = {"1 KiB", "1 MiB", "100 MiB"};

        int runs = 30;
        std::vector<std::vector<double>> hybrid_times(sizes.size(), std::vector<double>(runs, 0.0));

        std::cout << "Running Hybrid Encryption Benchmark (" << runs << " runs)...\n";

        byte aesKey[32];
        byte iv[12];
        rng.GenerateBlock(aesKey, sizeof(aesKey));
        rng.GenerateBlock(iv, sizeof(iv));

        for (size_t i = 0; i < sizes.size(); i++) {
            std::string payload(sizes[i], 'D');
            
            for (int r = 0; r < runs; r++) {
                auto start = high_resolution_clock::now();

                // Hybrid Process
                GCM<AES>::Encryption gcm;
                gcm.SetKeyWithIV(aesKey, sizeof(aesKey), iv, sizeof(iv));

                std::string ciphertext;
                AuthenticatedEncryptionFilter ef(gcm, new StringSink(ciphertext), false, 16);
                ef.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(payload.data()), payload.size());
                ef.ChannelMessageEnd(DEFAULT_CHANNEL);

                std::string encryptedAesKey;
                StringSource ss(aesKey, sizeof(aesKey), true, new PK_EncryptorFilter(rng, rsaEncryptor, new StringSink(encryptedAesKey)));

                auto stop = high_resolution_clock::now();
                hybrid_times[i][r] = duration_cast<milliseconds>(stop - start).count();
            }
            
            double avg_duration = 0;
            for(int r = 0; r < runs; r++) avg_duration += hybrid_times[i][r];
            avg_duration /= runs;

            std::cout << "Hybrid Encrypt " << names[i] << ": " << avg_duration << " ms (avg) ";
            if (avg_duration > 0) {
                double mb_per_sec = (sizes[i] / (1024.0 * 1024.0)) / (avg_duration / 1000.0);
                std::cout << "(" << mb_per_sec << " MiB/s)\n";
            } else {
                std::cout << "(too fast to measure throughput)\n";
            }
        }

        // Write Hybrid CSV
        std::string csvName = "hybrid_benchmark.csv";
        std::ofstream csv(csvName);
        csv << "Run,1KiB_ms,1MiB_ms,100MiB_ms\n";
        for (int r = 0; r < runs; r++) {
            csv << r << "," << hybrid_times[0][r] << "," << hybrid_times[1][r] << "," << hybrid_times[2][r] << "\n";
        }
        std::cout << "Saved Hybrid results to " << csvName << "\n";
    }

    void RunAllBenchmarks() {
        std::cout << "Starting Lab 3 Benchmarks...\n";
        BenchmarkRSA(3072);
        BenchmarkRSA(4096);
        BenchmarkHybrid();
    }
}
