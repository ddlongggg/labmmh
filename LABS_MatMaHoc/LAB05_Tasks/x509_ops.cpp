// src/x509_ops.cpp
#include "../include/crypto_lib.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>
#include <iostream>
#include <cstdio> // For remove()

// --- Helper: Unique pointers for OpenSSL types ---
template<typename T, void (*Func)(T*)>
using ossl_unique_ptr = std::unique_ptr<T, decltype(Func)>;

using BIO_ptr = ossl_unique_ptr<BIO, BIO_free_all>;
using X509_ptr = ossl_unique_ptr<X509, X509_free>;
using EVP_PKEY_ptr = ossl_unique_ptr<EVP_PKEY, EVP_PKEY_free>;

// Forward declarations for helpers/functions from other files
// (Ideally, these would be in included headers)
void handle_openssl_error(const char* context);
bool verify_ecdsa(const std::string& public_key_path, const std::string& message_path, const std::string& signature_path);
bool verify_rsapss(const std::string& public_key_path, const std::string& message_path, const std::string& signature_path);

// Helper to load an X.509 certificate from a file
X509_ptr load_certificate(const std::string& cert_path) {
    BIO_ptr cert_bio(BIO_new_file(cert_path.c_str(), "rb"), BIO_free_all); // Corrected init
    if (!cert_bio) {
        handle_openssl_error("BIO_new_file for loading certificate");
        return X509_ptr(nullptr, X509_free); // Corrected return
    }
    X509* cert_raw = PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr);
    if (!cert_raw) {
        handle_openssl_error("PEM_read_bio_X509");
        return X509_ptr(nullptr, X509_free); // Corrected return
    }
    return X509_ptr(cert_raw, X509_free); // Corrected init
}

// --- X.509 Operations Implementations ---

bool extract_pubkey_from_cert(const std::string& certificate_path, const std::string& public_key_path) {
    X509_ptr cert = load_certificate(certificate_path);
    if (!cert) {
        return false;
    }

    // Extract the public key from the certificate
    // X509_get_pubkey returns an internal pointer, but increments its reference count.
    // It needs to be freed with EVP_PKEY_free.
    EVP_PKEY* pkey_raw = X509_get_pubkey(cert.get());
    if (!pkey_raw) {
        handle_openssl_error("X509_get_pubkey");
        return false;
    }
    EVP_PKEY_ptr pkey(pkey_raw, EVP_PKEY_free); // Corrected init

    // Write the extracted public key to the specified file
    BIO_ptr pub_bio(BIO_new_file(public_key_path.c_str(), "wb"), BIO_free_all); // Corrected init
    if (!pub_bio) {
        handle_openssl_error("BIO_new_file for extracted public key");
        return false;
    }
    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) != 1) {
        handle_openssl_error("PEM_write_bio_PUBKEY for extracted key");
        return false;
    }

    return true;
}

bool verify_signature_with_cert(const std::string& certificate_path, const std::string& message_path, const std::string& signature_path) {
    X509_ptr cert = load_certificate(certificate_path);
    if (!cert) {
        return false;
    }

    // Extract the public key from the certificate
    EVP_PKEY* pkey_raw = X509_get_pubkey(cert.get());
     if (!pkey_raw) {
        handle_openssl_error("X509_get_pubkey for verification");
        return false;
    }
    EVP_PKEY_ptr pkey(pkey_raw, EVP_PKEY_free); // Corrected init

    // Determine the key type and call the appropriate verification function
    int key_type = EVP_PKEY_base_id(pkey.get());

    // We need to write the extracted public key to a temporary file
    // because our existing verify functions expect a file path.
    // A more integrated approach would pass the EVP_PKEY* directly.
    std::string temp_pubkey_path = "/tmp/temp_cert_pubkey.pem"; // Use a more robust temp file mechanism in production
    BIO_ptr temp_pub_bio(BIO_new_file(temp_pubkey_path.c_str(), "wb"), BIO_free_all); // Corrected init
    if (!temp_pub_bio) {
        handle_openssl_error("BIO_new_file for temporary public key");
        return false;
    }
    if (PEM_write_bio_PUBKEY(temp_pub_bio.get(), pkey.get()) != 1) {
        handle_openssl_error("PEM_write_bio_PUBKEY for temporary key");
        remove(temp_pubkey_path.c_str()); // Clean up temp file on error
        return false;
    }
    // Ensure the BIO is flushed before proceeding
    BIO_flush(temp_pub_bio.get());
    // Close the BIO to ensure file is written before reading
    temp_pub_bio.reset(); // This calls BIO_free_all

    bool result = false;
    if (key_type == EVP_PKEY_EC) {
        std::cout << "Verifying using ECDSA (key from certificate)..." << std::endl;
        result = verify_ecdsa(temp_pubkey_path, message_path, signature_path);
    } else if (key_type == EVP_PKEY_RSA) {
        std::cout << "Verifying using RSASSA-PSS (key from certificate)..." << std::endl;
        // NOTE: Assumes the signature was created with PSS padding if the key is RSA.
        // A more robust system might need metadata about the signature algorithm.
        result = verify_rsapss(temp_pubkey_path, message_path, signature_path);
    } else {
        std::cerr << "Error: Unsupported key type in certificate for verification (" << OBJ_nid2sn(key_type) << ")." << std::endl;
        result = false;
    }

    // Clean up the temporary file
    remove(temp_pubkey_path.c_str());

    return result;
}

