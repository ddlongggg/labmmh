#include <iostream>
#include <vector>
#include <chrono>
#include <string>
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

using namespace std;
using namespace std::chrono;

int print_errors_cb(const char *str, size_t len, void *u) {
    cerr << str;
    return 1;
}

void print_errors() {
    ERR_print_errors_cb(print_errors_cb, NULL);
}

struct BenchResult {
    string algo;
    string operation;
    size_t msgSize;
    double latencyMs;
    double throughputMBps;
};

vector<BenchResult> results;

void record_result(const string& algo, const string& op, size_t size, double ms, int ops) {
    double latency = ms / ops;
    double throughput = 0;
    if (size > 0) {
        throughput = (size * ops) / (ms / 1000.0) / (1024.0 * 1024.0);
    } else {
        throughput = ops / (ms / 1000.0); // Ops/sec for Keygen, Encaps, Decaps
    }
    results.push_back({algo, op, size, latency, throughput});
}

vector<uint8_t> generate_payload(size_t size) {
    vector<uint8_t> p(size);
    for(size_t i = 0; i < size; ++i) p[i] = rand() % 256;
    return p;
}

void warmup() {
    cout << "Warming up caches for 1 second..." << endl;
    auto start = high_resolution_clock::now();
    while (duration<double>(high_resolution_clock::now() - start).count() < 1.0) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_MD_CTX_free(ctx);
    }
}

void benchmark_mldsa(const string& algo, const vector<size_t>& sizes, int runs, int ops) {
    cout << "\n=== Benchmarking " << algo << " ===" << endl;
    
    // Keygen Benchmark
    EVP_PKEY* pkey = nullptr;
    for (int r = 0; r < runs; ++r) {
        auto start = high_resolution_clock::now();
        for (int i = 0; i < ops; ++i) {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, algo.c_str(), NULL);
            EVP_PKEY_keygen_init(ctx);
            EVP_PKEY_keygen(ctx, &pkey);
            EVP_PKEY_CTX_free(ctx);
            if (i < ops - 1 || r < runs - 1) {
                EVP_PKEY_free(pkey);
                pkey = nullptr;
            }
        }
        auto end = high_resolution_clock::now();
        double ms = duration<double, milli>(end - start).count();
        record_result(algo, "KeyGen", 0, ms, ops);
    }
    
    // Sign / Verify Benchmark
    for (size_t size : sizes) {
        cout << "  Payload Size: " << size << " bytes" << endl;
        vector<uint8_t> msg = generate_payload(size);
        
        // Optimize loops based on payload size to prevent excessive running times
        int current_ops = ops;
        if (size >= 1024 * 1024) current_ops = 50; // Reduce ops for 1MB+
        if (size >= 8 * 1024 * 1024) current_ops = 10; // Reduce ops for 8MB
        
        for (int r = 0; r < runs; ++r) {
            // Sign
            vector<uint8_t> sig;
            auto start_sign = high_resolution_clock::now();
            for (int i = 0; i < current_ops; ++i) {
                EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
                EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, NULL, pkey, NULL);
                size_t sig_len = 0;
                EVP_DigestSign(md_ctx, NULL, &sig_len, msg.data(), msg.size());
                sig.resize(sig_len);
                EVP_DigestSign(md_ctx, sig.data(), &sig_len, msg.data(), msg.size());
                sig.resize(sig_len);
                EVP_MD_CTX_free(md_ctx);
            }
            auto end_sign = high_resolution_clock::now();
            double ms_sign = duration<double, milli>(end_sign - start_sign).count();
            record_result(algo, "Sign", size, ms_sign, current_ops);
            
            // Verify
            auto start_verify = high_resolution_clock::now();
            for (int i = 0; i < current_ops; ++i) {
                EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
                EVP_DigestVerifyInit_ex(md_ctx, NULL, NULL, NULL, NULL, pkey, NULL);
                int res = EVP_DigestVerify(md_ctx, sig.data(), sig.size(), msg.data(), msg.size());
                if (res <= 0) cout << "Verification failed!" << endl;
                EVP_MD_CTX_free(md_ctx);
            }
            auto end_verify = high_resolution_clock::now();
            double ms_verify = duration<double, milli>(end_verify - start_verify).count();
            record_result(algo, "Verify", size, ms_verify, current_ops);
        }
    }
    
    if (pkey) EVP_PKEY_free(pkey);
}

void benchmark_mlkem(const string& algo, int runs, int ops) {
    cout << "\n=== Benchmarking " << algo << " ===" << endl;
    
    // Keygen
    EVP_PKEY* pkey = nullptr;
    for (int r = 0; r < runs; ++r) {
        auto start = high_resolution_clock::now();
        for (int i = 0; i < ops; ++i) {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, algo.c_str(), NULL);
            EVP_PKEY_keygen_init(ctx);
            EVP_PKEY_keygen(ctx, &pkey);
            EVP_PKEY_CTX_free(ctx);
            if (i < ops - 1 || r < runs - 1) {
                EVP_PKEY_free(pkey);
                pkey = nullptr;
            }
        }
        auto end = high_resolution_clock::now();
        double ms = duration<double, milli>(end - start).count();
        record_result(algo, "KeyGen", 0, ms, ops);
    }
    
    // Encapsulate / Decapsulate
    for (int r = 0; r < runs; ++r) {
        vector<uint8_t> ct, ss;
        // Encaps
        auto start_encaps = high_resolution_clock::now();
        for (int i = 0; i < ops; ++i) {
            EVP_PKEY_CTX* ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            EVP_PKEY_encapsulate_init(ectx, NULL);
            size_t outlen, secretlen;
            EVP_PKEY_encapsulate(ectx, NULL, &outlen, NULL, &secretlen);
            ct.resize(outlen); ss.resize(secretlen);
            EVP_PKEY_encapsulate(ectx, ct.data(), &outlen, ss.data(), &secretlen);
            EVP_PKEY_CTX_free(ectx);
        }
        auto end_encaps = high_resolution_clock::now();
        double ms_encaps = duration<double, milli>(end_encaps - start_encaps).count();
        record_result(algo, "Encaps", 0, ms_encaps, ops);
        
        // Decaps
        auto start_decaps = high_resolution_clock::now();
        for (int i = 0; i < ops; ++i) {
            EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
            EVP_PKEY_decapsulate_init(dctx, NULL);
            size_t secretlen2;
            EVP_PKEY_decapsulate(dctx, NULL, &secretlen2, ct.data(), ct.size());
            vector<uint8_t> ss2(secretlen2);
            EVP_PKEY_decapsulate(dctx, ss2.data(), &secretlen2, ct.data(), ct.size());
            EVP_PKEY_CTX_free(dctx);
        }
        auto end_decaps = high_resolution_clock::now();
        double ms_decaps = duration<double, milli>(end_decaps - start_decaps).count();
        record_result(algo, "Decaps", 0, ms_decaps, ops);
    }
    
    if (pkey) EVP_PKEY_free(pkey);
}

int main() {
    OSSL_PROVIDER* prov = OSSL_PROVIDER_load(NULL, "default");
    if (!prov) {
        cerr << "Failed to load default provider" << endl;
        print_errors();
    }
    
    srand(42);
    vector<size_t> sizes = {1024, 16 * 1024, 1024 * 1024, 8 * 1024 * 1024}; // 1KiB, 16KiB, 1MiB, 8MiB
    
    int runs = 30; // 30 independent runs per case for 95% CI plotting
    int ops = 100; // 100 rounds per block (adjusted dynamically for large payloads inside)
    
    try {
        warmup();
        benchmark_mldsa("ML-DSA-44", sizes, runs, ops);
        benchmark_mldsa("ML-DSA-65", sizes, runs, ops);
        benchmark_mlkem("ML-KEM-512", runs, 1000); // 1000 ops for ML-KEM
        
        ofstream out("benchmark_results.csv");
        out << "Algorithm,Operation,MessageSize,LatencyMs,Throughput\n";
        for (const auto& r : results) {
            out << r.algo << "," << r.operation << "," << r.msgSize << "," 
                << r.latencyMs << "," << r.throughputMBps << "\n";
        }
        cout << "\nBenchmarks finished. Results written to benchmark_results.csv\n";
        
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }
    
    if (prov) OSSL_PROVIDER_unload(prov);
    return 0;
}
