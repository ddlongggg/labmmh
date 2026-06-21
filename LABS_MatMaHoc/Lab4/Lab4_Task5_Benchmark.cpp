#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <openssl/evp.h>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

void generate_dummy_file(const std::string& filename, size_t size_mb) {
    std::cout << "Generating dummy file " << filename << " (" << size_mb << " MB)...\n";
    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Could not create dummy file.");
    }
    std::vector<char> buffer(1024 * 1024, 'A'); // 1MB buffer
    for (size_t i = 0; i < size_mb; ++i) {
        out.write(buffer.data(), buffer.size());
    }
    out.close();
    std::cout << "File generated.\n";
}

double hash_stream(const std::string& algo, const std::string& filename, size_t file_size_bytes, int ops) {
    const EVP_MD* md = EVP_get_digestbyname(algo.c_str());
    if (!md) throw std::runtime_error("Unknown algorithm: " + algo);

    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open file");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const size_t buffer_size = 8192; // 8KB buffer
    std::vector<char> buffer(buffer_size);

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < ops; ++i) {
        EVP_DigestInit_ex(ctx, md, nullptr);
        
        file.clear();
        file.seekg(0, std::ios::beg);
        
        while (file.good()) {
            file.read(buffer.data(), buffer_size);
            std::streamsize bytes = file.gcount();
            if (bytes > 0) {
                EVP_DigestUpdate(ctx, buffer.data(), bytes);
            }
        }
        std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
        unsigned int digest_len = 0;
        EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
    }

    auto end = std::chrono::high_resolution_clock::now();
    EVP_MD_CTX_free(ctx);

    std::chrono::duration<double> diff = end - start;
    double total_mb = static_cast<double>(file_size_bytes * ops) / (1024.0 * 1024.0);
    return total_mb / diff.count(); // MB/s
}

double hash_mmap(const std::string& algo, const std::string& filename, size_t file_size_bytes, int ops) {
    const EVP_MD* md = EVP_get_digestbyname(algo.c_str());
    if (!md) throw std::runtime_error("Unknown algorithm: " + algo);

#ifdef _WIN32
    HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) throw std::runtime_error("CreateFileA failed");

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        throw std::runtime_error("CreateFileMappingA failed");
    }

    void* mappedData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!mappedData) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        throw std::runtime_error("MapViewOfFile failed");
    }
#else
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd == -1) throw std::runtime_error("open failed");

    void* mappedData = mmap(NULL, file_size_bytes, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mappedData == MAP_FAILED) {
        close(fd);
        throw std::runtime_error("mmap failed");
    }
#endif

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < ops; ++i) {
        EVP_DigestInit_ex(ctx, md, nullptr);
        EVP_DigestUpdate(ctx, mappedData, file_size_bytes);

        std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
        unsigned int digest_len = 0;
        EVP_DigestFinal_ex(ctx, digest.data(), &digest_len);
    }

    auto end = std::chrono::high_resolution_clock::now();

    EVP_MD_CTX_free(ctx);
#ifdef _WIN32
    UnmapViewOfFile(mappedData);
    CloseHandle(hMapping);
    CloseHandle(hFile);
#else
    munmap(mappedData, file_size_bytes);
    close(fd);
#endif

    std::chrono::duration<double> diff = end - start;
    double total_mb = static_cast<double>(file_size_bytes * ops) / (1024.0 * 1024.0);
    return total_mb / diff.count(); // MB/s
}

void run_benchmark(const std::string& algo, const std::string& filename, size_t file_size_mb, int runs, int ops, std::ofstream& csv) {
    size_t bytes = file_size_mb * 1024 * 1024;
    std::cout << std::left << std::setw(15) << algo << " | ";
    
    double stream_sum = 0, mmap_sum = 0;

    for (int r = 0; r < runs; ++r) {
        double speed_stream = hash_stream(algo, filename, bytes, ops);
        double speed_mmap = hash_mmap(algo, filename, bytes, ops);
        
        stream_sum += speed_stream;
        mmap_sum += speed_mmap;
        
        // Write to CSV
        // Algo, FileSize_MB, Run, Ops, Stream_MBps, MMap_MBps
        csv << algo << "," << file_size_mb << "," << r << "," << ops << "," 
            << speed_stream << "," << speed_mmap << "\n";
    }
    
    std::cout << "Stream: " << std::fixed << std::setprecision(2) << std::setw(8) << (stream_sum/runs) << " MB/s (avg) | ";
    std::cout << "MMap: " << std::fixed << std::setprecision(2) << std::setw(8) << (mmap_sum/runs) << " MB/s (avg)\n";
}

int main() {
    OpenSSL_add_all_digests();

    std::vector<size_t> sizes = {1, 100}; // 1 MiB, 100 MiB
    std::vector<std::string> algos = {"SHA256", "SHA512", "SHA3-256", "SHA3-512"};
    int runs = 30;
    
    // NOTE: 100 ops on 100MB file takes a very long time (10GB per run). 
    // We adjust ops depending on file size to keep benchmark feasible.
    // User requested 100 ops. We'll set ops=100 for 1MB, and ops=10 for 100MB to avoid 2-hour benchmarks,
    // but we can enforce strictly ops=100 if the user absolutely wants to wait.
    // Let's stick strictly to 100 ops for both to satisfy the prompt exactly.
    int ops_1mb = 100;
    int ops_100mb = 100; // Warning: 30 runs * 100 ops * 100MB = 300GB hashing per algo.

    try {
        for (size_t s : sizes) {
            std::string csv_file = "hashing_benchmark_" + std::to_string(s) + "MB.csv";
            std::ofstream csv(csv_file);
            if (csv) {
                csv << "Algorithm,FileSize_MB,Run,Ops,Stream_MBps,MMap_MBps\n";
            }

            int current_ops = (s == 1) ? ops_1mb : ops_100mb;
            std::string fname = "dummy_" + std::to_string(s) + "MB.bin";
            generate_dummy_file(fname, s);

            std::cout << "\n--- Benchmark for " << s << " MiB File (" << runs << " runs, " << current_ops << " ops) ---\n";
            std::cout << "Warning: Large ops on 100MB file may take several minutes per algorithm...\n";
            
            for (const auto& algo : algos) {
                run_benchmark(algo, fname, s, runs, current_ops, csv);
            }
            std::cout << "-------------------------------------\n";
            
            // Clean up dummy file
            std::remove(fname.c_str());
            csv.close();
            std::cout << "Saved " << s << " MiB results to " << csv_file << "\n";
        }
        std::cout << "\nAll benchmark results saved successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }

    return 0;
}
