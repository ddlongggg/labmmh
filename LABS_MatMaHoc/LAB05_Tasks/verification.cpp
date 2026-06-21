// ============================================================================
// File: verification.cpp
//
// Self-contained OpenSSL 3.x signature verification DLL/shared-library module.
//
// This revision intentionally does NOT depend on a custom project header.
// All LIB_API exported C functions are placed near the beginning of this file.
// Internal C++ implementations remain below and continue to use std::string,
// std::vector, RAII unique_ptr, and OpenSSL EVP objects.
// ============================================================================

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include <vector>
#include <memory>
#include <iostream>
#include <string>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <cstddef>
#include <cstdio>

// ============================================================================
// DLL EXPORT MACRO
// ============================================================================
//
// Build DLL/shared library:
//   -DLIB_EXPORTS
//
// Windows:
//   extern "C" __declspec(dllexport)
//
// Linux/macOS:
//   extern "C" __attribute__((visibility("default"))) when exporting
//
// extern "C" prevents C++ name mangling for API functions, making the DLL easy
// to call from C, Python ctypes, C#, Java/JNA/JNI, etc.
// ============================================================================

#ifndef LIB_API
    #ifdef _WIN32
        #if defined(RSAKEYGEN_BUILD_DLL) || defined(LIB_EXPORTS)
            #define LIB_API extern "C" __declspec(dllexport)
        #elif defined(LIB_IMPORTS)
            #define LIB_API extern "C" __declspec(dllimport)
        #else
            #define LIB_API extern "C"
        #endif
    #else
        #if defined(RSAKEYGEN_BUILD_DLL) || defined(LIB_EXPORTS)
            #define LIB_API extern "C" __attribute__((visibility("default")))
        #else
            #define LIB_API extern "C"
        #endif
    #endif
#endif

// ============================================================================
// INTERNAL C++ IMPLEMENTATION FORWARD DECLARATIONS
// ============================================================================
//
// These declarations allow the exported C API block to stay near the beginning
// of the translation unit. The real C++ implementations remain below.
// ============================================================================

void handle_openssl_error(const char* context);

bool read_file_bytes(
    const std::string& file_path,
    std::vector<unsigned char>& data);

bool verify_ecdsa(
    const std::string& public_key_path,
    const std::string& message_path,
    const std::string& signature_path);

bool verify_rsapss(
    const std::string& public_key_path,
    const std::string& message_path,
    const std::string& signature_path);

// ============================================================================
// EXPORTED C API BLOCK
// ============================================================================
//
// All LIB_API functions are intentionally placed near the beginning.
//
// C API rules:
//   - Do not expose std::string, std::vector, std::unique_ptr, EVP_PKEY_ptr, etc.
//   - Use plain const char* file paths and POD output parameters.
//   - Any buffer allocated by this DLL must be released by free_memory().
//   - C++ exceptions are caught and do not cross the C ABI boundary.
// ============================================================================

namespace
{
    thread_local std::string g_last_api_error;

    void clear_last_api_error() noexcept
    {
        try
        {
            g_last_api_error.clear();
        }
        catch (...)
        {
        }
    }

    void set_last_api_error(const char* message) noexcept
    {
        try
        {
            g_last_api_error = message ? message : "Unknown API error";
        }
        catch (...)
        {
        }
    }
}

LIB_API
const char* get_last_error() noexcept
{
    return g_last_api_error.c_str();
}

LIB_API
void free_memory(void* p) noexcept
{
    std::free(p);
}

LIB_API
bool read_file_bytes(
    const char* file_path,
    unsigned char** out_data,
    size_t* out_size) noexcept
{
    clear_last_api_error();

    if (!file_path || !out_data || !out_size)
    {
        set_last_api_error(
            "read_file_bytes requires non-null file_path, out_data, and out_size.");
        return false;
    }

    *out_data = nullptr;
    *out_size = 0;

    try
    {
        std::vector<unsigned char> data;

        if (!::read_file_bytes(std::string(file_path), data))
        {
            set_last_api_error("read_file_bytes failed.");
            return false;
        }

        *out_size = data.size();

        if (data.empty())
        {
            return true;
        }

        unsigned char* out =
            static_cast<unsigned char*>(std::malloc(data.size()));

        if (!out)
        {
            set_last_api_error("Out of memory while allocating file buffer.");
            *out_size = 0;
            return false;
        }

        std::memcpy(out, data.data(), data.size());
        *out_data = out;

        return true;
    }
    catch (const std::exception& e)
    {
        set_last_api_error(e.what());
        *out_data = nullptr;
        *out_size = 0;
        return false;
    }
    catch (...)
    {
        set_last_api_error("Unknown exception in read_file_bytes.");
        *out_data = nullptr;
        *out_size = 0;
        return false;
    }
}

LIB_API
bool verify_ecdsa(
    const char* public_key_path,
    const char* message_path,
    const char* signature_path) noexcept
{
    clear_last_api_error();

    if (!public_key_path || !message_path || !signature_path)
    {
        set_last_api_error(
            "verify_ecdsa requires non-null public_key_path, message_path, and signature_path.");
        return false;
    }

    try
    {
        if (!::verify_ecdsa(
                std::string(public_key_path),
                std::string(message_path),
                std::string(signature_path)))
        {
            set_last_api_error("verify_ecdsa failed or signature is invalid.");
            return false;
        }

        return true;
    }
    catch (const std::exception& e)
    {
        set_last_api_error(e.what());
        return false;
    }
    catch (...)
    {
        set_last_api_error("Unknown exception in verify_ecdsa.");
        return false;
    }
}

LIB_API
bool verify_rsapss(
    const char* public_key_path,
    const char* message_path,
    const char* signature_path) noexcept
{
    clear_last_api_error();

    if (!public_key_path || !message_path || !signature_path)
    {
        set_last_api_error(
            "verify_rsapss requires non-null public_key_path, message_path, and signature_path.");
        return false;
    }

    try
    {
        if (!::verify_rsapss(
                std::string(public_key_path),
                std::string(message_path),
                std::string(signature_path)))
        {
            set_last_api_error("verify_rsapss failed or signature is invalid.");
            return false;
        }

        return true;
    }
    catch (const std::exception& e)
    {
        set_last_api_error(e.what());
        return false;
    }
    catch (...)
    {
        set_last_api_error("Unknown exception in verify_rsapss.");
        return false;
    }
}

// --- Helper: Unique pointers for OpenSSL types ---
template<typename T, void (*Func)(T*)>
using ossl_unique_ptr = std::unique_ptr<T, decltype(Func)>;

using BIO_ptr = ossl_unique_ptr<BIO, BIO_free_all>;
using EVP_PKEY_ptr = ossl_unique_ptr<EVP_PKEY, EVP_PKEY_free>;
using EVP_MD_CTX_ptr = ossl_unique_ptr<EVP_MD_CTX, EVP_MD_CTX_free>;
using EVP_PKEY_CTX_ptr = ossl_unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;

// Forward declarations for helpers (or include helpers.h)
// Need definition of handle_openssl_error, read_file_bytes
void handle_openssl_error(const char* context);
bool read_file_bytes(const std::string& file_path, std::vector<unsigned char>& data);


// ============================================================================
// INTERNAL HELPER: OpenSSL error reporting
// ============================================================================

void handle_openssl_error(const char* context)
{
    std::cerr
        << "\n[OpenSSL Error] "
        << (context ? context : "OpenSSL operation")
        << "\n";

    ERR_print_errors_fp(stderr);
}

// ============================================================================
// INTERNAL HELPER: Read entire binary file
// ============================================================================

bool read_file_bytes(
    const std::string& file_path,
    std::vector<unsigned char>& data)
{
    std::ifstream file(
        file_path,
        std::ios::binary | std::ios::ate
    );

    if (!file.is_open())
    {
        std::cerr << "Cannot open file: " << file_path << "\n";
        return false;
    }

    const std::streamsize size = file.tellg();

    if (size < 0)
    {
        std::cerr << "Cannot determine file size: " << file_path << "\n";
        return false;
    }

    file.seekg(0, std::ios::beg);
    data.resize(static_cast<std::size_t>(size));

    if (size > 0)
    {
        if (!file.read(
                reinterpret_cast<char*>(data.data()),
                size))
        {
            std::cerr << "Cannot read file: " << file_path << "\n";
            data.clear();
            return false;
        }
    }

    return true;
}

// Helper to load public key (implementation)
EVP_PKEY_ptr load_public_key(const std::string& key_path) {
    BIO_ptr key_bio(BIO_new_file(key_path.c_str(), "rb"), BIO_free_all); // Corrected init
    if (!key_bio) {
        handle_openssl_error("BIO_new_file for loading public key");
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free); // Corrected return
    }
    EVP_PKEY* pkey_raw = PEM_read_bio_PUBKEY(key_bio.get(), nullptr, nullptr, nullptr);
    if (!pkey_raw) {
        handle_openssl_error("PEM_read_bio_PUBKEY");
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free); // Corrected return
    }
    return EVP_PKEY_ptr(pkey_raw, EVP_PKEY_free); // Corrected init
}

// --- Verification Implementations ---

bool verify_ecdsa(const std::string& public_key_path, const std::string& message_path, const std::string& signature_path) {
    EVP_PKEY_ptr pkey = load_public_key(public_key_path);
    if (!pkey) {
        return false;
    }

    // Check if the key is ECDSA
    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_EC) {
        std::cerr << "Error: Provided key is not an EC key for ECDSA verification." << std::endl;
        return false;
    }

    std::vector<unsigned char> message_data;
    if (!read_file_bytes(message_path, message_data)) {
        return false;
    }

    std::vector<unsigned char> signature_data;
    if (!read_file_bytes(signature_path, signature_data)) {
        return false;
    }

    EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free); // Corrected init
    if (!md_ctx) {
        handle_openssl_error("EVP_MD_CTX_new for verification");
        return false;
    }

    const EVP_MD* md = EVP_sha256(); // Must match the digest used for signing

    if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, md, nullptr, pkey.get()) <= 0) {
        handle_openssl_error("EVP_DigestVerifyInit");
        return false;
    }

    if (EVP_DigestVerifyUpdate(md_ctx.get(), message_data.data(), message_data.size()) <= 0) {
        handle_openssl_error("EVP_DigestVerifyUpdate");
        return false;
    }

    // EVP_DigestVerifyFinal returns 1 for success (valid signature), 0 for failure (invalid signature),
    // and a negative value for other errors.
    int verify_result = EVP_DigestVerifyFinal(md_ctx.get(), signature_data.data(), signature_data.size());

    if (verify_result == 1) {
        return true; // Signature is valid
    } else if (verify_result == 0) {
        std::cerr << "Verification failed: Signature is invalid." << std::endl;
        return false; // Signature is invalid
    } else {
        handle_openssl_error("EVP_DigestVerifyFinal");
        return false; // An error occurred during verification
    }
}

bool verify_rsapss(const std::string& public_key_path, const std::string& message_path, const std::string& signature_path) {
    EVP_PKEY_ptr pkey = load_public_key(public_key_path);
    if (!pkey) {
        return false;
    }

    // Check if the key is RSA
    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA) {
        std::cerr << "Error: Provided key is not an RSA key for RSASSA-PSS verification." << std::endl;
        return false;
    }

    std::vector<unsigned char> message_data;
    if (!read_file_bytes(message_path, message_data)) {
        return false;
    }

    std::vector<unsigned char> signature_data;
    if (!read_file_bytes(signature_path, signature_data)) {
        return false;
    }

    // Calculate message hash (SHA256)
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;
    const EVP_MD* md = EVP_sha256();
    if (!EVP_Digest(message_data.data(), message_data.size(), digest.data(), &digest_len, md, nullptr)) {
        handle_openssl_error("EVP_Digest (calculate hash for PSS verify)");
        return false;
    }
    digest.resize(digest_len);

    // --- Verify the signature using PSS padding ---
    EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new(pkey.get(), nullptr), EVP_PKEY_CTX_free); // Corrected init
    if (!pctx) {
        handle_openssl_error("EVP_PKEY_CTX_new for PSS verification");
        return false;
    }

    if (EVP_PKEY_verify_init(pctx.get()) <= 0) {
        handle_openssl_error("EVP_PKEY_verify_init");
        return false;
    }

    // Set padding to PSS
    if (EVP_PKEY_CTX_set_rsa_padding(pctx.get(), RSA_PKCS1_PSS_PADDING) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_padding (PSS)");
        return false;
    }

    // Set PSS salt length (must match the one used for signing, e.g., -1 for hash length)
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx.get(), -1) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_pss_saltlen");
        return false;
    }

    // Set the digest type used for MGF1 and the message hashing (must match signing)
    if (EVP_PKEY_CTX_set_signature_md(pctx.get(), md) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_signature_md");
        return false;
    }

    // Perform verification
    // EVP_PKEY_verify returns 1 for success, 0 for failure, <0 for error
    int verify_result = EVP_PKEY_verify(pctx.get(), signature_data.data(), signature_data.size(), digest.data(), digest.size());

    if (verify_result == 1) {
        return true; // Signature is valid
    } else if (verify_result == 0) {
        std::cerr << "Verification failed: RSASSA-PSS Signature is invalid." << std::endl;
        return false; // Signature is invalid
    } else {
        handle_openssl_error("EVP_PKEY_verify");
        return false; // An error occurred
    }
}

