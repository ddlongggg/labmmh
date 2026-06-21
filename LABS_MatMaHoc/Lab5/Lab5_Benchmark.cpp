#include <iostream>
#include <vector>
#include <chrono>
#include <string>
#include <fstream>
#include <iomanip>

// Crypto++ Includes
#include "cryptlib.h"
#include "eccrypto.h"
#include "osrng.h"
#include "oids.h"
#include "rsa.h"
#include "pssr.h"
#include "sha.h"

using namespace CryptoPP;

struct BenchResult {
    std::string algo;
    std::string operation;
    size_t msgSize;
    double latencyMs;
    double throughputOpsSec;
};

std::vector<BenchResult> results;

void RecordResult(const std::string& algo, const std::string& op, size_t size, double ms, int iterations) {
    double latency = ms / iterations;
    double ops_sec = iterations / (ms / 1000.0);
    results.push_back({algo, op, size, latency, ops_sec});
}

// -------------------------------------------------------------------------
// ECDSA Benchmark
// -------------------------------------------------------------------------
void BenchmarkECDSA(size_t msgSize) {
    AutoSeededRandomPool prng;
    ECDSA<ECP, SHA256>::PrivateKey privKey;
    privKey.Initialize(prng, ASN1::secp256r1());

    ECDSA<ECP, SHA256>::PublicKey pubKey;
    privKey.MakePublicKey(pubKey);

    ECDSA<ECP, SHA256>::Signer signer(privKey);
    ECDSA<ECP, SHA256>::Verifier verifier(pubKey);

    std::vector<byte> message(msgSize, 0xAA);
    std::string signature;

    const int RUNS = 30;
    const int OPS = 500;
    
    // Benchmark Sign
    for (int r = 0; r < RUNS; ++r) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < OPS; ++i) {
            signature.clear();
            StringSource ss(message.data(), message.size(), true, 
                new SignerFilter(prng, signer, new StringSink(signature))
            );
        }
        auto end = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(end - start).count();
        RecordResult("ECDSA-P256", "Sign", msgSize, ms, OPS);
    }

    // Benchmark Verify
    for (int r = 0; r < RUNS; ++r) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < OPS; ++i) {
            bool result = false;
            StringSource ss(std::string((char*)message.data(), message.size()) + signature, true,
                new SignatureVerificationFilter(verifier, new ArraySink((byte*)&result, sizeof(result)),
                    SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_END
                )
            );
            if (!result) throw std::runtime_error("ECDSA verification failed during benchmark!");
        }
        auto end = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(end - start).count();
        RecordResult("ECDSA-P256", "Verify", msgSize, ms, OPS);
    }
}

// -------------------------------------------------------------------------
// RSA-PSS Benchmark
// -------------------------------------------------------------------------
void BenchmarkRSAPSS(size_t msgSize) {
    AutoSeededRandomPool prng;
    RSA::PrivateKey privKey;
    privKey.GenerateRandomWithKeySize(prng, 3072);

    RSA::PublicKey pubKey(privKey);

    RSASS<PSS, SHA256>::Signer signer(privKey);
    RSASS<PSS, SHA256>::Verifier verifier(pubKey);

    std::vector<byte> message(msgSize, 0xAA);
    std::string signature;

    const int RUNS = 30;
    const int OPS = 500;
    
    // Benchmark Sign
    for (int r = 0; r < RUNS; ++r) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < OPS; ++i) {
            signature.clear();
            StringSource ss(message.data(), message.size(), true, 
                new SignerFilter(prng, signer, new StringSink(signature))
            );
        }
        auto end = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(end - start).count();
        RecordResult("RSA-PSS-3072", "Sign", msgSize, ms, OPS);
    }

    // Benchmark Verify
    for (int r = 0; r < RUNS; ++r) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < OPS; ++i) {
            bool result = false;
            StringSource ss(std::string((char*)message.data(), message.size()) + signature, true,
                new SignatureVerificationFilter(verifier, new ArraySink((byte*)&result, sizeof(result)),
                    SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_END
                )
            );
            if (!result) throw std::runtime_error("RSA-PSS verification failed during benchmark!");
        }
        auto end = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(end - start).count();
        RecordResult("RSA-PSS-3072", "Verify", msgSize, ms, OPS);
    }
}

int main() {
    try {
        std::vector<size_t> sizes = {
            1024,           // 1 KiB
            16 * 1024,      // 16 KiB
            1024 * 1024,    // 1 MiB
            8 * 1024 * 1024 // 8 MiB
        };

        std::cout << "Starting Benchmarks...\n";

        for (size_t size : sizes) {
            std::cout << "Benchmarking size: " << size << " bytes\n";
            BenchmarkECDSA(size);
            BenchmarkRSAPSS(size);
        }

        std::ofstream out("benchmark_results.csv");
        out << "Algorithm,Operation,MessageSize,LatencyMs,ThroughputOpsSec\n";
        for (const auto& r : results) {
            out << r.algo << "," << r.operation << "," << r.msgSize << "," 
                << r.latencyMs << "," << r.throughputOpsSec << "\n";
        }

        std::cout << "Benchmarks finished. Results written to benchmark_results.csv\n";
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ Exception: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Standard Exception: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown Exception\n";
        return 1;
    }
    return 0;
}
