// src/key_generation.cpp
#include "include/crypto_lib.h"
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <fstream>
#include <memory>

// --- Helper: Unique pointers for OpenSSL types ---
template<typename T, void (*Func)(T*)>
using ossl_unique_ptr = std::unique_ptr<T, decltype(Func)>;

// --- Helper: Unique pointers for save/load key, file ---
using BIO_ptr = ossl_unique_ptr<BIO, BIO_free_all>;
using EVP_PKEY_ptr = ossl_unique_ptr<EVP_PKEY, EVP_PKEY_free>;

// --- Helper: Unique pointers for gen key, csr ---
using BIO_ptr = ossl_unique_ptr<BIO, BIO_free_all>;
using EVP_PKEY_ptr = ossl_unique_ptr<EVP_PKEY, EVP_PKEY_free>;
using EVP_PKEY_CTX_ptr = ossl_unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using X509_REQ_ptr = ossl_unique_ptr<X509_REQ, X509_REQ_free>;
using X509_ptr = ossl_unique_ptr<X509, X509_free>;
using X509_NAME_ptr = ossl_unique_ptr<X509_NAME, X509_NAME_free>;
using ASN1_INTEGER_ptr = ossl_unique_ptr<ASN1_INTEGER, ASN1_INTEGER_free>;


// --- File I/O Helpers ---
// Open file in binary mode and read all bytes into the vector
bool read_file_bytes(const std::string& file_path, std::vector<unsigned char>& data) {
    // Open file in binary mode and move to the end to get size
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file for reading: " << file_path << std::endl;
        return false;
    }
    // Get file size and read contents
    std::streamsize size = file.tellg();
    // Check for empty file
    if (size == 0) {
        std::cerr << "Warning: File is empty: " << file_path << std::endl;
        return true;
    }
    // Reset file position to the beginning before reading
    file.seekg(0, std::ios::beg);
    // Resize vector to hold file contents and read
    data.resize(size);
    // Read file contents into vector
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        std::cerr << "Error: Failed to read file: " << file_path << std::endl;
        return false;
    }
    return true;
}
// Open file in binary mode and write all bytes from the vector
bool write_file_bytes(const std::string& file_path, const std::vector<unsigned char>& data) {
    // Open file in binary mode for writing
    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file for writing: " << file_path << std::endl;
        return false;
    }
    // Write data from vector to file
    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        std::cerr << "Error: Failed to write to file: " << file_path << std::endl;
        return false;
    }
    return true;
}

// --- Base64 Helper ---
std::string base64_encode(const std::vector<unsigned char>& input) {
    // Create a BIO chain with base64 filter and memory sink
    BIO_ptr b64(BIO_new(BIO_f_base64()), BIO_free_all);
    // Set the flag to avoid newlines in the output
    BIO_ptr bmem(BIO_new(BIO_s_mem()), BIO_free_all);
    //No newlines in base64 output, set the flag
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    // Chain the BIOs: base64 filter on top of memory sink
    BIO_push(b64.get(), bmem.get());
    // Write input data to the BIO chain
    if (BIO_write(b64.get(), input.data(), input.size()) <= 0) {
        handle_openssl_error("BIO_write for base64 encode");
        return "";
    }
    // Flush the BIO to ensure all data is processed
    if (BIO_flush(b64.get()) != 1) {
        handle_openssl_error("BIO_flush for base64 encode");
        return "";
    }
    // Get the pointer to the memory buffer and its length
    BUF_MEM *bptr = nullptr;
    // BIO_get_mem_ptr returns a pointer to the internal buffer of the memory BIO
    BIO_get_mem_ptr(bmem.get(), &bptr);
    // Check if the buffer pointer is valid and has data
    if (!bptr || !bptr->data || bptr->length == 0) {
        handle_openssl_error("BIO_get_mem_ptr for base64 encode");
        return "";
    }
    // Create a std::string from the base64 encoded data in the buffer
    std::string result(bptr->data, bptr->length);
    return result;
}

// --- Key Loading Helper ---
// This function attempts to load a private key from the specified file path.
EVP_PKEY_ptr load_private_key(const std::string& key_path) {
    // Open the key file using a BIO. We will try multiple formats, so we keep the BIO open for multiple attempts.
    BIO_ptr key_bio(BIO_new_file(key_path.c_str(), "rb"), BIO_free_all);
    if (!key_bio) {
        handle_openssl_error("BIO_new_file for loading private key");
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free); // Corrected return for unique_ptr
    }
    // Try reading as PKCS8 first, then specific types if needed. This allows for more flexible key loading.
    EVP_PKEY *pkey_raw = PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr);
    if (!pkey_raw) {
        // Reset BIO position if first read failed
        BIO_ctrl(key_bio.get(), BIO_CTRL_RESET, 0, nullptr);
        // Try reading as RSA specifically (older format)
        RSA *rsa_raw = PEM_read_bio_RSAPrivateKey(key_bio.get(), nullptr, nullptr, nullptr);
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
             EC_KEY *ec_raw = PEM_read_bio_ECPrivateKey(key_bio.get(), nullptr, nullptr, nullptr);
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
        // Return an empty unique_ptr on failure
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }
    // Return the loaded key wrapped in a unique_ptr for automatic memory management
    return EVP_PKEY_ptr(pkey_raw, EVP_PKEY_free);
}

// --- Error Handling ---
void handle_openssl_error(const char* context) {
    std::cerr << "OpenSSL Error in " << context << ":\n";
    ERR_print_errors_fp(stderr);
}

// --- Key Generation Implementations ---
// These functions generate ECDSA and RSA key pairs, write them to files, and handle errors appropriately.
bool generate_ecdsa_keypair(const std::string& curve_name, const std::string& private_key_path, const std::string& public_key_path) {
    // Create a new EVP_PKEY_CTX for EC key generation using the specified curve. We use a unique_ptr to ensure it is freed properly.
    EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    // Check if the context was created successfully
    if (!pctx) {
        handle_openssl_error("EVP_PKEY_CTX_new_id for EC");
        return false;
    }
    // Initialize the key generation operation. This prepares the context for generating a key pair.
    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen_init");
        return false;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), OBJ_txt2nid(curve_name.c_str())) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid");
        return false;
    }
    // Generate the key pair. The generated key will be stored in pkey_raw, which we will manage with a unique_ptr for automatic cleanup.
    EVP_PKEY *pkey_raw = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey_raw) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen");
        return false;
    }
    // Wrap the raw pointer in a unique_ptr to ensure it is freed properly when it goes out of scope, even if an error occurs later.
    EVP_PKEY_ptr pkey(pkey_raw, EVP_PKEY_free);

    // Write private key
    BIO_ptr priv_bio(BIO_new_file(private_key_path.c_str(), "wb"), BIO_free_all);
    // Check if the BIO for the private key file was created successfully
    if (!priv_bio) {
        handle_openssl_error("BIO_new_file for private key");
        return false;
    }
    if (PEM_write_bio_PrivateKey(priv_bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        handle_openssl_error("PEM_write_bio_PrivateKey");
        return false;
    }

    // Write public key
    BIO_ptr pub_bio(BIO_new_file(public_key_path.c_str(), "wb"), BIO_free_all); 
    // Check if the BIO for the public key file was created successfully
    if (!pub_bio) {
        handle_openssl_error("BIO_new_file for public key");
        return false;
    }
    // Write the public key in PEM format.
    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) != 1) {
        handle_openssl_error("PEM_write_bio_PUBKEY");
        return false;
    }

    return true;
}

bool generate_rsa_keypair(int bits, const std::string& private_key_path, const std::string& public_key_path) {
    EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!pctx) {
        handle_openssl_error("EVP_PKEY_CTX_new_id for RSA");
        return false;
    }

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen_init");
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx.get(), bits) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_keygen_bits");
        return false;
    }

    EVP_PKEY *pkey_raw = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey_raw) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen");
        return false;
    }
    EVP_PKEY_ptr pkey(pkey_raw, EVP_PKEY_free); // Corrected init

    // Write private key
    BIO_ptr priv_bio(BIO_new_file(private_key_path.c_str(), "wb"), BIO_free_all); // Corrected init
    if (!priv_bio) {
        handle_openssl_error("BIO_new_file for private key");
        return false;
    }
    // Use traditional format for broader compatibility, can use PKCS8 as well
    // Note: EVP_PKEY_get0_RSA returns an internal pointer, do not free it.
    const RSA* rsa_key = EVP_PKEY_get0_RSA(pkey.get());
    if (!rsa_key) {
        handle_openssl_error("EVP_PKEY_get0_RSA");
        return false;
    }
    if (PEM_write_bio_RSAPrivateKey(priv_bio.get(), rsa_key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
         handle_openssl_error("PEM_write_bio_RSAPrivateKey");
         return false;
    }

    // Write public key
    BIO_ptr pub_bio(BIO_new_file(public_key_path.c_str(), "wb"), BIO_free_all); // Corrected init
    if (!pub_bio) {
        handle_openssl_error("BIO_new_file for public key");
        return false;
    }
    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) != 1) {
        handle_openssl_error("PEM_write_bio_PUBKEY");
        return false;
    }

    return true;
}

// Helper to load private key (moved to helpers.cpp, but keep a local version for now if needed)
// Or better: ensure helpers.cpp is linked correctly and remove this duplicate.
// Assuming helpers.cpp is linked, we declare it here:
EVP_PKEY_ptr load_private_key(const std::string& key_path);

bool generate_csr(const std::string& private_key_path, const std::string& csr_path, const std::vector<std::string>& subject_info) {
    EVP_PKEY_ptr pkey = load_private_key(private_key_path);
    if (!pkey) {
        return false;
    }

    X509_REQ_ptr req(X509_REQ_new(), X509_REQ_free);
    if (!req) {
        handle_openssl_error("X509_REQ_new");
        return false;
    }

    // Set version (typically 0 for CSRs)
    if (X509_REQ_set_version(req.get(), 0L) != 1) {
        handle_openssl_error("X509_REQ_set_version");
        return false;
    }

    // Set subject name
    X509_NAME* name = X509_REQ_get_subject_name(req.get()); // Internal pointer
    if (!name) {
        handle_openssl_error("X509_REQ_get_subject_name");
        return false;
    }
    for (const auto& entry : subject_info) {
        size_t eq_pos = entry.find("=");
        if (eq_pos == std::string::npos || eq_pos == 0 || eq_pos == entry.length() - 1) {
            std::cerr << "Error: Invalid subject entry format: " << entry << std::endl;
            return false;
        }
        std::string key = entry.substr(0, eq_pos);
        std::string value = entry.substr(eq_pos + 1);
        if (X509_NAME_add_entry_by_txt(name, key.c_str(), MBSTRING_ASC, (const unsigned char*)value.c_str(), -1, -1, 0) != 1) {
            handle_openssl_error("X509_NAME_add_entry_by_txt");
            return false;
        }
    }

    // Set public key
    if (X509_REQ_set_pubkey(req.get(), pkey.get()) != 1) {
        handle_openssl_error("X509_REQ_set_pubkey");
        return false;
    }

    // Sign the CSR with the private key
    const EVP_MD* digest = EVP_sha256(); // Use SHA256 for signing
    if (X509_REQ_sign(req.get(), pkey.get(), digest) <= 0) {
        handle_openssl_error("X509_REQ_sign");
        return false;
    }

    // Write CSR to file
    BIO_ptr csr_bio(BIO_new_file(csr_path.c_str(), "wb"), BIO_free_all); // Corrected init
    if (!csr_bio) {
        handle_openssl_error("BIO_new_file for CSR");
        return false;
    }
    if (PEM_write_bio_X509_REQ(csr_bio.get(), req.get()) != 1) {
        handle_openssl_error("PEM_write_bio_X509_REQ");
        return false;
    }

    return true;
}

// Helper to load CSR
X509_REQ_ptr load_csr(const std::string& csr_path) {
    BIO_ptr csr_bio(BIO_new_file(csr_path.c_str(), "rb"), BIO_free_all); // Corrected init
    if (!csr_bio) {
        handle_openssl_error("BIO_new_file for loading CSR");
        return X509_REQ_ptr(nullptr, X509_REQ_free); // Corrected return
    }
    X509_REQ* req_raw = PEM_read_bio_X509_REQ(csr_bio.get(), nullptr, nullptr, nullptr);
    if (!req_raw) {
        handle_openssl_error("PEM_read_bio_X509_REQ");
        return X509_REQ_ptr(nullptr, X509_REQ_free); // Corrected return
    }
    return X509_REQ_ptr(req_raw, X509_REQ_free); // Corrected init
}

bool generate_self_signed_certificate(const std::string& csr_path, const std::string& private_key_path, const std::string& certificate_path, int days) {
    X509_REQ_ptr req = load_csr(csr_path);
    if (!req) {
        return false;
    }

    EVP_PKEY_ptr ca_pkey = load_private_key(private_key_path);
    if (!ca_pkey) {
        return false;
    }

    // Verify CSR signature (optional but good practice)
    // X509_REQ_get_pubkey returns an internal pointer managed by the X509_REQ object,
    // but it's safer to manage it with its own unique_ptr if used outside the immediate scope.
    // However, since we use it immediately for verification and setting in the cert, we can use the raw pointer carefully.
    // For robustness, using a unique_ptr is better practice.
    EVP_PKEY* req_pubkey_raw = X509_REQ_get_pubkey(req.get());
    if (!req_pubkey_raw) {
         handle_openssl_error("X509_REQ_get_pubkey");
         return false;
    }
    EVP_PKEY_ptr req_pubkey(req_pubkey_raw, EVP_PKEY_free); // Manage with unique_ptr

    if (X509_REQ_verify(req.get(), req_pubkey.get()) != 1) {
        handle_openssl_error("X509_REQ_verify failed (CSR signature invalid or key mismatch)");
        return false;
    }

    X509_ptr cert(X509_new(), X509_free);
    if (!cert) {
        handle_openssl_error("X509_new");
        return false;
    }

    // Set version (X.509 v3)
    if (X509_set_version(cert.get(), 2L) != 1) { // Version is 0-based, so 2 means v3
        handle_openssl_error("X509_set_version");
        return false;
    }

    // Set serial number (use something simple for self-signed, e.g., 1)
    ASN1_INTEGER_ptr serial(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    if (!serial || !ASN1_INTEGER_set(serial.get(), 1L)) {
        handle_openssl_error("ASN1_INTEGER_set or new");
        return false;
    }
    if (X509_set_serialNumber(cert.get(), serial.get()) != 1) {
        handle_openssl_error("X509_set_serialNumber");
        return false;
    }
    // serial ownership is transferred to cert, no need to free here.

    // Set issuer name (same as subject for self-signed)
    X509_NAME* subject_name = X509_REQ_get_subject_name(req.get()); // Internal pointer
    if (X509_set_issuer_name(cert.get(), subject_name) != 1) {
        handle_openssl_error("X509_set_issuer_name");
        return false;
    }

    // Set validity period
    if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0)) {
        handle_openssl_error("X509_gmtime_adj (notBefore)");
        return false;
    }
    if (!X509_gmtime_adj(X509_getm_notAfter(cert.get()), (long)60 * 60 * 24 * days)) {
        handle_openssl_error("X509_gmtime_adj (notAfter)");
        return false;
    }

    // Set subject name (from CSR)
    if (X509_set_subject_name(cert.get(), subject_name) != 1) {
        handle_openssl_error("X509_set_subject_name");
        return false;
    }

    // Set public key (from CSR)
    if (X509_set_pubkey(cert.get(), req_pubkey.get()) != 1) {
        handle_openssl_error("X509_set_pubkey");
        return false;
    }

    // Sign the certificate with the CA private key (which is our key for self-signed)
    const EVP_MD* digest = EVP_sha256();
    if (X509_sign(cert.get(), ca_pkey.get(), digest) <= 0) {
        handle_openssl_error("X509_sign");
        return false;
    }

    // Write certificate to file
    BIO_ptr cert_bio(BIO_new_file(certificate_path.c_str(), "wb"), BIO_free_all); // Corrected init
    if (!cert_bio) {
        handle_openssl_error("BIO_new_file for certificate");
        return false;
    }
    if (PEM_write_bio_X509(cert_bio.get(), cert.get()) != 1) {
        handle_openssl_error("PEM_write_bio_X509");
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " ecdsa <curve_name> <private_key.pem> <public_key.pem>\n"
                  << "  " << argv[0] << " rsa <bits> <private_key.pem> <public_key.pem>\n"
                  << "  " << argv[0] << " csr <private_key.pem> <csr.pem> <CN=CommonName,O=Org,...>\n"
                  << "  " << argv[0] << " selfsign <csr.pem> <private_key.pem> <cert.pem> <days>\n";
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "ecdsa") {
        if (argc != 5) {
            std::cerr << "Usage: " << argv[0] << " ecdsa <curve_name> <private_key.pem> <public_key.pem>\n";
            return 1;
        }
        std::string curve = argv[2];
        std::string priv_path = argv[3];
        std::string pub_path = argv[4];
        return generate_ecdsa_keypair(curve, priv_path, pub_path) ? 0 : 1;
    }

    if (mode == "rsa") {
        if (argc != 5) {
            std::cerr << "Usage: " << argv[0] << " rsa <bits> <private_key.pem> <public_key.pem>\n";
            return 1;
        }
        int bits = std::stoi(argv[2]);
        std::string priv_path = argv[3];
        std::string pub_path = argv[4];
        return generate_rsa_keypair(bits, priv_path, pub_path) ? 0 : 1;
    }

    if (mode == "csr") {
        if (argc != 5) {
            std::cerr << "Usage: " << argv[0] << " csr <private_key.pem> <csr.pem> <CN=...,O=...,...>\n";
            return 1;
        }
        std::string priv_key = argv[2];
        std::string csr_path = argv[3];
        std::string subject_string = argv[4];
        std::vector<std::string> subject_entries;

        size_t pos = 0;
        while ((pos = subject_string.find(",")) != std::string::npos) {
            subject_entries.push_back(subject_string.substr(0, pos));
            subject_string.erase(0, pos + 1);
        }
        subject_entries.push_back(subject_string); // last part
        return generate_csr(priv_key, csr_path, subject_entries) ? 0 : 1;
    }

    if (mode == "selfsign") {
        if (argc != 6) {
            std::cerr << "Usage: " << argv[0] << " selfsign <csr.pem> <private_key.pem> <cert.pem> <days>\n";
            return 1;
        }
        std::string csr = argv[2];
        std::string key = argv[3];
        std::string cert = argv[4];
        int days = std::stoi(argv[5]);
        return generate_self_signed_certificate(csr, key, cert, days) ? 0 : 1;
    }

    std::cerr << "Unknown command: " << mode << "\n";
    return 1;
}

