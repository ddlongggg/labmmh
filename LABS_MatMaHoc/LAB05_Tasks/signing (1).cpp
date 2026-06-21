// ============================================================================
// File: signing.cpp
//
// Modern OpenSSL 3.x Digital Signature Example
//
// Demonstrates:
//
// 1. ECDSA signing
// 2. RSA-PSS signing
// 3. EVP_DigestSign API
// 4. Secure SHA256 hashing
// 5. Modern OpenSSL 3.x usage
// 6. RAII memory management
//
// IMPORTANT:
//
// This file uses ONLY modern EVP APIs.
//
// Deprecated OpenSSL 1.x low-level APIs are avoided.
//
// ============================================================================

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <vector>
#include <memory>
#include <iostream>
#include <string>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <exception>

// ============================================================================
// DLL EXPORT MACRO
// ============================================================================
//
// LIB_API:
//
// Windows DLL:
//     extern "C" __declspec(dllexport)
//
// Linux/macOS:
//     extern "C"
//
// extern "C":
//     disables C++ name mangling
//
// This allows easier DLL usage from:
//
// - C
// - Python ctypes
// - C#
// - Java JNI
// - etc.
//
// ============================================================================

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


// ============================================================================
// INTERNAL C++ IMPLEMENTATION FORWARD DECLARATIONS
// ============================================================================
//
// These declarations keep the exported C API block near the beginning of this
// file while leaving the real C++ implementation below unchanged.
// The internal methods continue to use std::string, std::vector, RAII, and EVP.
// ============================================================================

void handle_openssl_error(const char* context);

bool read_file_bytes(
    const std::string& file_path,
    std::vector<unsigned char>& data);

bool write_file_bytes(
    const std::string& file_path,
    const std::vector<unsigned char>& data);

std::string base64_encode(
    const std::vector<unsigned char>& input);

bool sign_ecdsa(
    const std::string& private_key_path,
    const std::string& message_path,
    const std::string& signature_path);

bool sign_rsapss(
    const std::string& private_key_path,
    const std::string& message_path,
    const std::string& signature_path);

// ============================================================================
// EXPORTED C API BLOCK
//
// All LIB_API functions are intentionally placed near the beginning of the
// translation unit.  The implementation below is a thin C ABI layer only.
// Internal C++ methods remain below and keep their std::string/std::vector
// signatures.
//
// Memory rule:
//   - Any pointer returned through this C API must be released by free_memory().
//   - This prevents allocator/CRT mismatches across DLL boundaries.
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

    char* duplicate_c_string(const std::string& text) noexcept
    {
        char* out = static_cast<char*>(std::malloc(text.size() + 1));

        if (!out)
        {
            set_last_api_error("Out of memory while allocating output string.");
            return nullptr;
        }

        std::memcpy(out, text.data(), text.size());
        out[text.size()] = '\0';

        return out;
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
bool write_file_bytes(
    const char* file_path,
    const unsigned char* data,
    size_t size) noexcept
{
    clear_last_api_error();

    if (!file_path)
    {
        set_last_api_error("write_file_bytes requires non-null file_path.");
        return false;
    }

    if (size > 0 && !data)
    {
        set_last_api_error(
            "write_file_bytes requires non-null data when size is greater than zero.");
        return false;
    }

    try
    {
        std::vector<unsigned char> buffer;

        if (size > 0)
        {
            buffer.assign(data, data + size);
        }

        if (!::write_file_bytes(std::string(file_path), buffer))
        {
            set_last_api_error("write_file_bytes failed.");
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
        set_last_api_error("Unknown exception in write_file_bytes.");
        return false;
    }
}

LIB_API
char* base64_encode(
    const unsigned char* data,
    size_t size) noexcept
{
    clear_last_api_error();

    if (size > 0 && !data)
    {
        set_last_api_error(
            "base64_encode requires non-null data when size is greater than zero.");
        return nullptr;
    }

    try
    {
        if (size == 0)
        {
            return duplicate_c_string(std::string());
        }

        std::vector<unsigned char> buffer(data, data + size);
        std::string encoded = ::base64_encode(buffer);

        return duplicate_c_string(encoded);
    }
    catch (const std::exception& e)
    {
        set_last_api_error(e.what());
        return nullptr;
    }
    catch (...)
    {
        set_last_api_error("Unknown exception in base64_encode.");
        return nullptr;
    }
}

LIB_API
bool sign_ecdsa(
    const char* private_key_path,
    const char* message_path,
    const char* signature_path) noexcept
{
    clear_last_api_error();

    if (!private_key_path || !message_path || !signature_path)
    {
        set_last_api_error(
            "sign_ecdsa requires non-null private_key_path, message_path, and signature_path.");
        return false;
    }

    try
    {
        if (!::sign_ecdsa(
                std::string(private_key_path),
                std::string(message_path),
                std::string(signature_path)))
        {
            set_last_api_error("sign_ecdsa failed.");
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
        set_last_api_error("Unknown exception in sign_ecdsa.");
        return false;
    }
}

LIB_API
bool sign_rsapss(
    const char* private_key_path,
    const char* message_path,
    const char* signature_path) noexcept
{
    clear_last_api_error();

    if (!private_key_path || !message_path || !signature_path)
    {
        set_last_api_error(
            "sign_rsapss requires non-null private_key_path, message_path, and signature_path.");
        return false;
    }

    try
    {
        if (!::sign_rsapss(
                std::string(private_key_path),
                std::string(message_path),
                std::string(signature_path)))
        {
            set_last_api_error("sign_rsapss failed.");
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
        set_last_api_error("Unknown exception in sign_rsapss.");
        return false;
    }
}

// ============================================================================
// RAII SMART POINTER HELPERS
// ============================================================================
//
// OpenSSL internally uses:
//
//     malloc()
//     free()
//
// Without RAII:
//
//     memory leaks become common.
//
// Modern C++ solution:
//
//     std::unique_ptr
//
// ============================================================================

template<typename T, void (*Func)(T*)>
using ossl_unique_ptr =
    std::unique_ptr<T, decltype(Func)>;

// EVP_PKEY smart pointer
using EVP_PKEY_ptr =
    ossl_unique_ptr<EVP_PKEY, EVP_PKEY_free>;

// Message digest context smart pointer
using EVP_MD_CTX_ptr =
    ossl_unique_ptr<EVP_MD_CTX, EVP_MD_CTX_free>;

// Public/private key operation context smart pointer
using EVP_PKEY_CTX_ptr =
    ossl_unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;

// BIO smart pointer
using BIO_ptr =
    ossl_unique_ptr<BIO, BIO_free_all>;

// ============================================================================
// OPENSSL ERROR HELPER
// ============================================================================
//
// ERR_print_errors_fp(stderr):
//
// Prints OpenSSL internal error stack.
//
// ============================================================================

void handle_openssl_error(const char* context)
{
    std::cerr
        << "\n[OpenSSL Error] "
        << context
        << "\n";

    ERR_print_errors_fp(stderr);
}

// ============================================================================
// FILE INPUT HELPER
// ============================================================================
//
// Reads entire binary file into:
//
//     std::vector<unsigned char>
//
// Why unsigned char?
//
// Because cryptographic data is binary.
//
// ============================================================================

bool read_file_bytes(
    const std::string& file_path,
    std::vector<unsigned char>& data)
{
    // ------------------------------------------------------------------------
    // std::ios::ate
    //
    // Open file and immediately move cursor to END.
    //
    // Then tellg() gives total file size.
    // ------------------------------------------------------------------------

    std::ifstream file(
        file_path,
        std::ios::binary | std::ios::ate
    );

    if (!file.is_open())
    {
        std::cerr
            << "Cannot open file: "
            << file_path
            << "\n";

        return false;
    }

    // Get file size
    std::streamsize size = file.tellg();

    if (size < 0)
    {
        std::cerr
            << "Failed to determine file size.\n";

        return false;
    }

    // Empty file is valid
    if (size == 0)
    {
        data.clear();
        return true;
    }

    // Move cursor back to beginning
    file.seekg(0, std::ios::beg);

    // Resize vector
    data.resize(static_cast<size_t>(size));

    // ------------------------------------------------------------------------
    // reinterpret_cast<char*>
    //
    // ifstream::read requires char*
    //
    // But vector stores unsigned char
    //
    // So we reinterpret the pointer type.
    // ------------------------------------------------------------------------

    if (!file.read(
            reinterpret_cast<char*>(data.data()),
            size))
    {
        std::cerr
            << "Failed to read file.\n";

        return false;
    }

    return true;
}

// ============================================================================
// FILE OUTPUT HELPER
// ============================================================================

bool write_file_bytes(
    const std::string& file_path,
    const std::vector<unsigned char>& data)
{
    std::ofstream file(
        file_path,
        std::ios::binary
    );

    if (!file.is_open())
    {
        std::cerr
            << "Cannot open output file: "
            << file_path
            << "\n";

        return false;
    }

    if (!data.empty())
    {
        if (!file.write(
                reinterpret_cast<const char*>(data.data()),
                data.size()))
        {
            std::cerr
                << "Failed to write file.\n";

            return false;
        }
    }

    return true;
}

// ============================================================================
// BASE64 ENCODER
// ============================================================================
//
// BIO CHAIN:
//
// raw bytes
//     ↓
// base64 filter BIO
//     ↓
// memory BIO
//     ↓
// output string
//
// ============================================================================

std::string base64_encode(
    const std::vector<unsigned char>& input)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());

    if (!b64 || !mem)
    {
        BIO_free_all(b64);
        BIO_free_all(mem);

        handle_openssl_error("BIO_new");
        return "";
    }

    // Disable line wrapping
    BIO_set_flags(
        b64,
        BIO_FLAGS_BASE64_NO_NL
    );

    // BIO chain:
    //
    // b64 -> mem
    //
    b64 = BIO_push(b64, mem);

    if (BIO_write(
            b64,
            input.data(),
            static_cast<int>(input.size())) <= 0)
    {
        BIO_free_all(b64);

        handle_openssl_error("BIO_write");
        return "";
    }

    if (BIO_flush(b64) != 1)
    {
        BIO_free_all(b64);

        handle_openssl_error("BIO_flush");
        return "";
    }

    BUF_MEM* buffer_ptr = nullptr;

    BIO_get_mem_ptr(
        b64,
        &buffer_ptr
    );

    if (!buffer_ptr || !buffer_ptr->data)
    {
        BIO_free_all(b64);

        handle_openssl_error("BIO_get_mem_ptr");
        return "";
    }

    std::string result(
        buffer_ptr->data,
        buffer_ptr->length
    );

    BIO_free_all(b64);

    return result;
}

// ============================================================================
// LOAD PRIVATE KEY
// ============================================================================
//
// PEM_read_bio_PrivateKey():
//
// Modern OpenSSL generic key loader.
//
// Supports:
//
// - RSA
// - EC
// - Ed25519
// - DSA
// - etc.
//
// Returns:
//
//     EVP_PKEY
//
// EVP_PKEY is OpenSSL's generic key abstraction.
//
// ============================================================================

EVP_PKEY_ptr load_private_key(
    const std::string& key_path)
{
    BIO_ptr key_bio(
        BIO_new_file(key_path.c_str(), "rb"),
        BIO_free_all
    );

    if (!key_bio)
    {
        handle_openssl_error("BIO_new_file");

        return EVP_PKEY_ptr(
            nullptr,
            EVP_PKEY_free
        );
    }

    EVP_PKEY* raw_key =
        PEM_read_bio_PrivateKey(
            key_bio.get(),
            nullptr,
            nullptr,
            nullptr
        );

    if (!raw_key)
    {
        handle_openssl_error(
            "PEM_read_bio_PrivateKey");

        return EVP_PKEY_ptr(
            nullptr,
            EVP_PKEY_free
        );
    }

    return EVP_PKEY_ptr(
        raw_key,
        EVP_PKEY_free
    );
}

// ============================================================================
// ECDSA SIGNING
// ============================================================================
//
// ECDSA:
//
// Elliptic Curve Digital Signature Algorithm
//
// SIGNING FLOW:
//
// Message
//    ↓
// SHA256 hash
//    ↓
// ECDSA private key
//    ↓
// Signature
//
// IMPORTANT:
//
// Digital signatures DO NOT encrypt the entire message.
//
// Instead:
//
//     sign(hash(message))
//
// ============================================================================

bool sign_ecdsa(
    const std::string& private_key_path,
    const std::string& message_path,
    const std::string& signature_path)
{
    // ------------------------------------------------------------------------
    // Load private key
    // ------------------------------------------------------------------------

    EVP_PKEY_ptr pkey =
        load_private_key(private_key_path);

    if (!pkey)
    {
        return false;
    }

    // ------------------------------------------------------------------------
    // Ensure key type is EC
    // ------------------------------------------------------------------------

    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_EC)
    {
        std::cerr
            << "Error: Provided key is not an EC key.\n";

        return false;
    }

    // ------------------------------------------------------------------------
    // Read message file
    // ------------------------------------------------------------------------

    std::vector<unsigned char> message_data;

    if (!read_file_bytes(
            message_path,
            message_data))
    {
        return false;
    }

    // ------------------------------------------------------------------------
    // Create digest/signature context
    // ------------------------------------------------------------------------

    EVP_MD_CTX_ptr md_ctx(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free
    );

    if (!md_ctx)
    {
        handle_openssl_error(
            "EVP_MD_CTX_new");

        return false;
    }

    // ------------------------------------------------------------------------
    // Select SHA256
    // ------------------------------------------------------------------------

    const EVP_MD* md = EVP_sha256();

    // ------------------------------------------------------------------------
    // Initialize digest + signing operation
    //
    // OpenSSL internally:
    //
    // 1. hashes data
    // 2. signs digest
    // ------------------------------------------------------------------------

    if (EVP_DigestSignInit(
            md_ctx.get(),
            nullptr,
            md,
            nullptr,
            pkey.get()) <= 0)
    {
        handle_openssl_error(
            "EVP_DigestSignInit");

        return false;
    }

    // ------------------------------------------------------------------------
    // Feed message data
    // ------------------------------------------------------------------------

    if (EVP_DigestSignUpdate(
            md_ctx.get(),
            message_data.data(),
            message_data.size()) <= 0)
    {
        handle_openssl_error(
            "EVP_DigestSignUpdate");

        return false;
    }

    // ------------------------------------------------------------------------
    // First EVP_DigestSignFinal call:
    //
    // Query required signature size.
    // ------------------------------------------------------------------------

    size_t sig_len = 0;

    if (EVP_DigestSignFinal(
            md_ctx.get(),
            nullptr,
            &sig_len) <= 0)
    {
        handle_openssl_error(
            "EVP_DigestSignFinal(size)");

        return false;
    }

    // Allocate signature buffer
    std::vector<unsigned char> signature(sig_len);

    // ------------------------------------------------------------------------
    // Second EVP_DigestSignFinal call:
    //
    // Generate actual signature.
    // ------------------------------------------------------------------------

    if (EVP_DigestSignFinal(
            md_ctx.get(),
            signature.data(),
            &sig_len) <= 0)
    {
        handle_openssl_error(
            "EVP_DigestSignFinal(sign)");

        return false;
    }

    // Actual size may differ slightly
    signature.resize(sig_len);

    // ------------------------------------------------------------------------
    // Save signature
    // ------------------------------------------------------------------------

    if (!write_file_bytes(
            signature_path,
            signature))
    {
        return false;
    }

    // ------------------------------------------------------------------------
    // Optional:
    // print Base64 signature
    // ------------------------------------------------------------------------

    std::cout
        << "\n[ECDSA Signature - Base64]\n"
        << base64_encode(signature)
        << "\n";

    return true;
}

// ============================================================================
// RSA-PSS SIGNING
// ============================================================================
//
// RSA-PSS:
//
// RSA Probabilistic Signature Scheme
//
// Modern secure RSA signature standard.
//
// More secure than:
//
//     PKCS#1 v1.5 signatures
//
// SIGNING FLOW:
//
// Message
//    ↓
// SHA256
//    ↓
// PSS padding
//    ↓
// RSA private exponent operation
//    ↓
// Signature
//
// ============================================================================

bool sign_rsapss(
    const std::string& private_key_path,
    const std::string& message_path,
    const std::string& signature_path)
{
    // ------------------------------------------------------------------------
    // Load private key
    // ------------------------------------------------------------------------

    EVP_PKEY_ptr pkey =
        load_private_key(private_key_path);

    if (!pkey)
    {
        return false;
    }

    // ------------------------------------------------------------------------
    // Ensure key type is RSA
    // ------------------------------------------------------------------------

    if (EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA)
    {
        std::cerr
            << "Error: Provided key is not RSA.\n";

        return false;
    }

    // ------------------------------------------------------------------------
    // Read message file
    // ------------------------------------------------------------------------

    std::vector<unsigned char> message_data;

    if (!read_file_bytes(
            message_path,
            message_data))
    {
        return false;
    }

    // ------------------------------------------------------------------------
    // Create digest/signature context
    // ------------------------------------------------------------------------

    EVP_MD_CTX_ptr md_ctx(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free
    );

    if (!md_ctx)
    {
        handle_openssl_error(
            "EVP_MD_CTX_new");

        return false;
    }

    // SHA256 hashing algorithm
    const EVP_MD* md = EVP_sha256();

    // EVP_PKEY_CTX:
    //
    // stores algorithm-specific parameters
    //
    EVP_PKEY_CTX* pkey_ctx = nullptr;

    // ------------------------------------------------------------------------
    // Initialize signing operation
    // ------------------------------------------------------------------------

    if (EVP_DigestSignInit(
            md_ctx.get(),
            &pkey_ctx,
            md,
            nullptr,
            pkey.get()) <= 0)
    {
        handle_openssl_error(
            "EVP_DigestSignInit");

        return false;
    }

    // ------------------------------------------------------------------------
    // Configure RSA-PSS padding
    // ------------------------------------------------------------------------

    if (EVP_PKEY_CTX_set_rsa_padding(
            pkey_ctx,
            RSA_PKCS1_PSS_PADDING) <= 0)
    {
        handle_openssl_error(
            "EVP_PKEY_CTX_set_rsa_padding");

        return false;
    }

    // ------------------------------------------------------------------------
    // Configure PSS salt length
    //
    // -1:
    //
    // salt length = hash length
    //
    // SHA256 => 32-byte salt
    // ------------------------------------------------------------------------

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(
            pkey_ctx,
            -1) <= 0)
    {
        handle_openssl_error(
            "EVP_PKEY_CTX_set_rsa_pss_saltlen");

        return false;
    }

    // ------------------------------------------------------------------------
    // Feed message bytes
    // ------------------------------------------------------------------------

    if (EVP_DigestSignUpdate(
            md_ctx.get(),
            message_data.data(),
            message_data.size()) <= 0)
    {
        handle_openssl_error(
            "EVP_DigestSignUpdate");

        return false;
    }

    // ------------------------------------------------------------------------
    // Query required signature size
    // ------------------------------------------------------------------------

    size_t sig_len = 0;

    if (EVP_DigestSignFinal(
            md_ctx.get(),
            nullptr,
            &sig_len) <= 0)
    {
        handle_openssl_error(
            "EVP_DigestSignFinal(size)");

        return false;
    }

    std::vector<unsigned char> signature(sig_len);

    // ------------------------------------------------------------------------
    // Generate signature
    // ------------------------------------------------------------------------

    if (EVP_DigestSignFinal(
            md_ctx.get(),
            signature.data(),
            &sig_len) <= 0)
    {
        handle_openssl_error(
            "EVP_DigestSignFinal(sign)");

        return false;
    }

    // Resize to actual length
    signature.resize(sig_len);

    // ------------------------------------------------------------------------
    // Save signature
    // ------------------------------------------------------------------------

    if (!write_file_bytes(
            signature_path,
            signature))
    {
        return false;
    }

    // ------------------------------------------------------------------------
    // Optional:
    // print Base64 signature
    // ------------------------------------------------------------------------

    std::cout
        << "\n[RSA-PSS Signature - Base64]\n"
        << base64_encode(signature)
        << "\n";

    return true;
}
// ============================================================================
// OPTIONAL CLI TEST APPLICATION
// ============================================================================
//
// This main() is compiled ONLY when:
//
// RSAKEYGEN_BUILD_DLL is NOT defined
//
// Therefore:
//
// DLL build:
//     g++ -shared ... -DRSAKEYGEN_BUILD_DLL
//
// EXE build:
//     g++ signing_r1.cpp -o signing.exe ...
//
// ============================================================================

#ifndef RSAKEYGEN_BUILD_DLL

int main(int argc, char* argv[])
{
    std::cout << "========================================\n";
    std::cout << " OpenSSL Digital Signature Demo\n";
    std::cout << "========================================\n";

    // ------------------------------------------------------------------------
    // Expected command line:
    //
    // signing.exe <mode> <private_key> <message> <signature>
    //
    // Modes:
    //   ecdsa
    //   rsapss
    //
    // Example:
    //
    // signing.exe ecdsa private.pem msg.txt sig.bin
    //
    // signing.exe rsapss private.pem msg.txt sig.bin
    // ------------------------------------------------------------------------

    if (argc != 5)
    {
        std::cout << "\nUsage:\n";

        std::cout
            << "  " << argv[0]
            << " ecdsa  <private.pem> <message> <signature>\n";

        std::cout
            << "  " << argv[0]
            << " rsapss <private.pem> <message> <signature>\n";

        return 1;
    }

    std::string mode            = argv[1];
    std::string private_key     = argv[2];
    std::string message_file    = argv[3];
    std::string signature_file  = argv[4];

    bool success = false;

    // ------------------------------------------------------------------------
    // ECDSA
    // ------------------------------------------------------------------------

    if (mode == "ecdsa")
    {
        std::cout << "\n[+] Performing ECDSA signing...\n";

        success = sign_ecdsa(
            private_key,
            message_file,
            signature_file
        );
    }

    // ------------------------------------------------------------------------
    // RSA-PSS
    // ------------------------------------------------------------------------

    else if (mode == "rsapss")
    {
        std::cout << "\n[+] Performing RSA-PSS signing...\n";

        success = sign_rsapss(
            private_key,
            message_file,
            signature_file
        );
    }

    else
    {
        std::cerr
            << "\nInvalid mode.\n"
            << "Supported modes: ecdsa, rsapss\n";

        return 1;
    }

    // ------------------------------------------------------------------------
    // Final result
    // ------------------------------------------------------------------------

    if (success)
    {
        std::cout
            << "\n[+] Signature generated successfully.\n";

        std::cout
            << "[+] Output file: "
            << signature_file
            << "\n";

        return 0;
    }
    else
    {
        std::cerr
            << "\n[-] Signing failed.\n";

        return 1;
    }
}

#endif