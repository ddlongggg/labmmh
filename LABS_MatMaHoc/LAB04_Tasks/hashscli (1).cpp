#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <openssl/evp.h>

// ========================
// Utility: print hex
// ========================
void print_hex(const unsigned char* data, unsigned int len) {
    for (unsigned int i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

// ========================
// Hash Class
// ========================
class Hasher {
private:
    const EVP_MD* md;

public:
    Hasher(const std::string& algo) {
        OpenSSL_add_all_digests();

        md = EVP_get_digestbyname(algo.c_str());
        if (!md) {
            throw std::runtime_error("Unsupported hash algorithm: " + algo);
        }
    }

    std::vector<unsigned char> hash_data(const unsigned char* data, size_t len) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

        std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
        unsigned int digest_len = 0;

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1)
            throw std::runtime_error("DigestInit failed");

        if (EVP_DigestUpdate(ctx, data, len) != 1)
            throw std::runtime_error("DigestUpdate failed");

        if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1)
            throw std::runtime_error("DigestFinal failed");

        EVP_MD_CTX_free(ctx);

        digest.resize(digest_len);
        return digest;
    }

    std::vector<unsigned char> hash_file(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file)
            throw std::runtime_error("Cannot open file: " + filename);

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1)
            throw std::runtime_error("DigestInit failed");

        const size_t buffer_size = 4096;
        char buffer[buffer_size];

        while (file.good()) {
            file.read(buffer, buffer_size);
            std::streamsize bytes = file.gcount();
            if (bytes > 0) {
                if (EVP_DigestUpdate(ctx, buffer, bytes) != 1)
                    throw std::runtime_error("DigestUpdate failed");
            }
        }

        std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
        unsigned int digest_len = 0;

        if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1)
            throw std::runtime_error("DigestFinal failed");

        EVP_MD_CTX_free(ctx);

        digest.resize(digest_len);
        return digest;
    }
};

// ========================
// CLI Parsing
// ========================
void print_usage() {
    std::cout << "Usage:\n";
    std::cout << "  hash_cli <algorithm> -s \"text\"\n";
    std::cout << "  hash_cli <algorithm> -f <file>\n\n";

    std::cout << "Examples:\n";
    std::cout << "  hash_cli sha256 -s \"hello\"\n";
    std::cout << "  hash_cli sha3-256 -f input.txt\n";
}

// ========================
// Main
// ========================
int main(int argc, char* argv[]) {
    if (argc < 4) {
        print_usage();
        return 1;
    }

    std::string algorithm = argv[1];
    std::string mode = argv[2];

    try {
        Hasher hasher(algorithm);

        if (mode == "-s") {
            const char* text = argv[3];

            auto digest = hasher.hash_data(
                reinterpret_cast<const unsigned char*>(text),
                strlen(text)
            );

            std::cout << "Input (text): " << text << "\n";
            std::cout << "Algorithm: " << algorithm << "\n";
            std::cout << "Digest: ";
            print_hex(digest.data(), digest.size());
        }
        else if (mode == "-f") {
            std::string filename = argv[3];

            auto digest = hasher.hash_file(filename);

            std::cout << "Input (file): " << filename << "\n";
            std::cout << "Algorithm: " << algorithm << "\n";
            std::cout << "Digest: ";
            print_hex(digest.data(), digest.size());
        }
        else {
            print_usage();
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}