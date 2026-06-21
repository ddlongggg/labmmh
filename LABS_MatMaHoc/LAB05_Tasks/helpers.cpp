// src/helpers.cpp

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <memory>

// --- Helper: Unique pointers for OpenSSL types ---
template<typename T, void (*Func)(T*)>
using ossl_unique_ptr = std::unique_ptr<T, decltype(Func)>;

using BIO_ptr = ossl_unique_ptr<BIO, BIO_free_all>;
using EVP_PKEY_ptr = ossl_unique_ptr<EVP_PKEY, EVP_PKEY_free>;

// --- File I/O Helpers ---
bool read_file_bytes(const std::string& file_path, std::vector<unsigned char>& data) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file for reading: " << file_path << std::endl;
        return false;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    data.resize(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        std::cerr << "Error: Failed to read file: " << file_path << std::endl;
        return false;
    }
    return true;
}

bool write_file_bytes(const std::string& file_path, const std::vector<unsigned char>& data) {
    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file for writing: " << file_path << std::endl;
        return false;
    }
    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        std::cerr << "Error: Failed to write to file: " << file_path << std::endl;
        return false;
    }
    return true;
}

// --- Base64 Helper ---
std::string base64_encode(const std::vector<unsigned char>& input) {
    BIO_ptr b64(BIO_new(BIO_f_base64()), BIO_free_all);
    BIO_ptr bmem(BIO_new(BIO_s_mem()), BIO_free_all);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL); // No newlines in output
    BIO_push(b64.get(), bmem.get());

    if (BIO_write(b64.get(), input.data(), input.size()) <= 0) {
        handle_openssl_error("BIO_write for base64 encode");
        return "";
    }
    if (BIO_flush(b64.get()) != 1) {
        handle_openssl_error("BIO_flush for base64 encode");
        return "";
    }

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(bmem.get(), &bptr);
    if (!bptr || !bptr->data || bptr->length == 0) {
        handle_openssl_error("BIO_get_mem_ptr for base64 encode");
        return "";
    }

    std::string result(bptr->data, bptr->length);
    return result;
}

// --- Key Loading Helper ---
// Defined in key_generation.cpp, but needed here too. Ideally in helpers.cpp
// For now, we duplicate the definition. A better approach is linking object files.
EVP_PKEY_ptr load_private_key(const std::string& key_path) {
    BIO_ptr key_bio(BIO_new_file(key_path.c_str(), "rb"), BIO_free_all);
    if (!key_bio) {
        handle_openssl_error("BIO_new_file for loading private key");
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free); // Corrected return for unique_ptr
    }
    // Try reading as PKCS8 first, then specific types if needed
    EVP_PKEY* pkey_raw = PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr);
    if (!pkey_raw) {
        // Reset BIO position if first read failed
        BIO_ctrl(key_bio.get(), BIO_CTRL_RESET, 0, nullptr);
        // Try reading as RSA specifically (older format)
        RSA* rsa_raw = PEM_read_bio_RSAPrivateKey(key_bio.get(), nullptr, nullptr, nullptr);
        if (rsa_raw) {
            pkey_raw = EVP_PKEY_new();
            if (pkey_raw && EVP_PKEY_assign_RSA(pkey_raw, rsa_raw)) {
                // Success, EVP_PKEY owns rsa_raw now
            } else {
                RSA_free(rsa_raw);
                EVP_PKEY_free(pkey_raw);
                pkey_raw = nullptr;
            }
        } else {
             // Reset BIO position again
             BIO_ctrl(key_bio.get(), BIO_CTRL_RESET, 0, nullptr);
             // Try reading as EC specifically
             EC_KEY* ec_raw = PEM_read_bio_ECPrivateKey(key_bio.get(), nullptr, nullptr, nullptr);
             if (ec_raw) {
                 pkey_raw = EVP_PKEY_new();
                 if (pkey_raw && EVP_PKEY_assign_EC_KEY(pkey_raw, ec_raw)) {
                     // Success, EVP_PKEY owns ec_raw now
                 } else {
                     EC_KEY_free(ec_raw);
                     EVP_PKEY_free(pkey_raw);
                     pkey_raw = nullptr;
                 }
             }
        }
    }

    if (!pkey_raw) {
        handle_openssl_error("Failed to read private key (tried PKCS8, RSA, EC)");
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free); // Corrected return for unique_ptr
    }
    return EVP_PKEY_ptr(pkey_raw, EVP_PKEY_free);
}

