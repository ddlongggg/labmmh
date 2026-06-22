#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <map>
#include <iomanip>

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

std::string to_lower(std::string str) {
    for (auto& c : str) c = tolower(c);
    return str;
}

class Hasher {
private:
    const EVP_MD* md;
    std::string algo_name;
    bool is_xof;
    size_t xof_outlen;

public:
    Hasher(const std::string& algo, size_t outlen = 0) {
        OpenSSL_add_all_digests();
        algo_name = to_lower(algo);
        
        is_xof = (algo_name == "shake128" || algo_name == "shake256");
        xof_outlen = outlen;

        std::string ossl_algo = algo_name;
        if (algo_name == "sha224") ossl_algo = "SHA224";
        else if (algo_name == "sha256") ossl_algo = "SHA256";
        else if (algo_name == "sha384") ossl_algo = "SHA384";
        else if (algo_name == "sha512") ossl_algo = "SHA512";
        else if (algo_name == "sha3-224") ossl_algo = "SHA3-224";
        else if (algo_name == "sha3-256") ossl_algo = "SHA3-256";
        else if (algo_name == "sha3-384") ossl_algo = "SHA3-384";
        else if (algo_name == "sha3-512") ossl_algo = "SHA3-512";
        else if (algo_name == "shake128") ossl_algo = "SHAKE128";
        else if (algo_name == "shake256") ossl_algo = "SHAKE256";
        else {
            throw std::runtime_error("Unsupported hash algorithm: " + algo);
        }

        md = EVP_get_digestbyname(ossl_algo.c_str());
        if (!md) {
            throw std::runtime_error("Failed to initialize OpenSSL digest for: " + algo);
        }

        if (is_xof && xof_outlen == 0) {
            throw std::runtime_error("XOF algorithms (SHAKE) require --outlen parameter.");
        }
    }

    std::vector<unsigned char> hash_data(const unsigned char* data, size_t len) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("DigestInit failed");
        }

        if (EVP_DigestUpdate(ctx, data, len) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("DigestUpdate failed");
        }

        std::vector<unsigned char> digest;
        if (is_xof) {
            digest.resize(xof_outlen);
            if (EVP_DigestFinalXOF(ctx, digest.data(), xof_outlen) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("DigestFinalXOF failed");
            }
        } else {
            digest.resize(EVP_MD_size(md));
            unsigned int digest_len = 0;
            if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("DigestFinal failed");
            }
            digest.resize(digest_len);
        }

        EVP_MD_CTX_free(ctx);
        return digest;
    }

    std::vector<unsigned char> hash_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + filename);
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("DigestInit failed");
        }

        const size_t buffer_size = 4096;
        std::vector<char> buffer(buffer_size);

        while (file.good()) {
            file.read(buffer.data(), buffer_size);
            std::streamsize bytes = file.gcount();
            if (bytes > 0) {
                if (EVP_DigestUpdate(ctx, buffer.data(), bytes) != 1) {
                    EVP_MD_CTX_free(ctx);
                    throw std::runtime_error("DigestUpdate failed during file reading");
                }
            }
        }

        std::vector<unsigned char> digest;
        if (is_xof) {
            digest.resize(xof_outlen);
            if (EVP_DigestFinalXOF(ctx, digest.data(), xof_outlen) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("DigestFinalXOF failed");
            }
        } else {
            digest.resize(EVP_MD_size(md));
            unsigned int digest_len = 0;
            if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("DigestFinal failed");
            }
            digest.resize(digest_len);
        }

        EVP_MD_CTX_free(ctx);
        return digest;
    }
};

bool run_kats() {
    std::cout << "Running Known Answer Tests (KATs)...\n";
    
    Hasher sha256("sha256");
    auto res_sha256 = sha256.hash_data((const unsigned char*)"", 0);
    std::string expected_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    
    std::string hex_sha256 = "";
    for (auto b : res_sha256) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hex_sha256 += buf;
    }
    
    if (hex_sha256 != expected_sha256) {
        std::cerr << "[FAIL] SHA-256 KAT failed!\n";
        return false;
    }
    std::cout << "[PASS] SHA-256\n";

    Hasher shake256("shake256", 32);
    auto res_shake = shake256.hash_data((const unsigned char*)"", 0);
    std::string expected_shake = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
    std::string hex_shake = "";
    for (auto b : res_shake) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hex_shake += buf;
    }
    if (hex_shake != expected_shake) {
        std::cerr << "[FAIL] SHAKE256 KAT failed!\n";
        return false;
    }
    std::cout << "[PASS] SHAKE256\n";

    std::cout << "All KATs passed.\n\n";
    return true;
}

void print_usage() {
    std::cout << "Usage:\n";
    std::cout << "  hashtool kat\n";
    std::cout << "  hashtool --algo <algo> [--outlen <bytes>] --in <file> [--out <output_file>] [--stream]\n";
    std::cout << "Algorithms:\n";
    std::cout << "  sha224, sha256, sha384, sha512\n";
    std::cout << "  sha3-224, sha3-256, sha3-384, sha3-512\n";
    std::cout << "  shake128, shake256 (requires --outlen)\n";
}

int main(int argc, char* argv[]) {
    if (argc >= 2 && std::string(argv[1]) == "kat") {
        // Chạy độc lập chế độ kiểm thử KAT
        if (!run_kats()) {
            std::cerr << "Fatal error: Cryptographic self-tests failed. Halting.\n";
            return 1;
        }
        return 0;
    }

    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string algo = "";
    std::string infile = "";
    std::string outfile = "";
    size_t outlen = 0;
    bool stream = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--algo" && i + 1 < argc) algo = argv[++i];
        else if (arg == "--in" && i + 1 < argc) infile = argv[++i];
        else if (arg == "--out" && i + 1 < argc) outfile = argv[++i];
        else if (arg == "--outlen" && i + 1 < argc) outlen = std::stoull(std::string(argv[++i]));
        else if (arg == "--stream") stream = true;
        else {
            std::cerr << "Unknown or incomplete argument: " << arg << "\n";
            print_usage();
            return 1;
        }
    }

    if (algo.empty() || infile.empty()) {
        std::cerr << "Missing required arguments: --algo and --in\n";
        print_usage();
        return 1;
    }

    try {
        Hasher hasher(algo, outlen);
        
        auto digest = hasher.hash_file(infile);

        if (!outfile.empty()) {
            std::ofstream out(outfile, std::ios::binary);
            if (!out) {
                throw std::runtime_error("Could not open output file for writing.");
            }
            out.write(reinterpret_cast<const char*>(digest.data()), digest.size());
            std::cout << "Raw binary digest written to: " << outfile << "\n";
        } else {
            std::cout << "Digest (Hex): ";
            print_hex(digest.data(), digest.size());
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
