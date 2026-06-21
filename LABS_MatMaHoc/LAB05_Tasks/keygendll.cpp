// ============================================================================
// File: key_generation.cpp
//
// Modern OpenSSL 3.x Example
//
// This program demonstrates:
//
// 1. RSA key generation
// 2. ECDSA key generation
// 3. PEM file writing
// 4. PEM file reading
// 5. CSR generation
// 6. Self-signed certificate generation
// 7. OpenSSL EVP API usage
// 8. RAII using std::unique_ptr
// 9. EXE + DLL dual build architecture
//
// ============================================================================

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <string>
#include <cstring>
#include <cstdlib>
#include <exception>

// ============================================================================
// RAII SMART POINTER HELPERS
// ============================================================================

template<typename T, void(*FreeFunc)(T*)>
using ossl_unique_ptr = std::unique_ptr<T, decltype(FreeFunc)>;

using BIO_ptr          = ossl_unique_ptr<BIO, BIO_free_all>;
using EVP_PKEY_ptr     = ossl_unique_ptr<EVP_PKEY, EVP_PKEY_free>;
using EVP_PKEY_CTX_ptr = ossl_unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using X509_REQ_ptr     = ossl_unique_ptr<X509_REQ, X509_REQ_free>;
using X509_ptr         = ossl_unique_ptr<X509, X509_free>;
using ASN1_INTEGER_ptr = ossl_unique_ptr<ASN1_INTEGER, ASN1_INTEGER_free>;

// ============================================================================
// DLL EXPORT MACRO
// ============================================================================

#ifdef _WIN32

    #ifdef LIB_EXPORTS

        // Building DLL
        #define LIB_API extern "C" __declspec(dllexport)

    #else

        // Normal EXE / static build
        #define LIB_API extern "C"

    #endif

#else

    #ifdef LIB_EXPORTS

        // Linux / macOS shared-library build
        #define LIB_API extern "C" __attribute__((visibility("default")))

    #else

        // Normal EXE / static build
        #define LIB_API extern "C"

    #endif

#endif

// ============================================================================
// INTERNAL C++ IMPLEMENTATION FORWARD DECLARATIONS
// ============================================================================

void handle_openssl_error(const std::string& context);

bool read_file_bytes(
    const std::string& file_path,
    std::vector<unsigned char>& data);

bool write_file_bytes(
    const std::string& file_path,
    const std::vector<unsigned char>& data);

std::string base64_encode(
    const std::vector<unsigned char>& input);

EVP_PKEY_ptr load_private_key(
    const std::string& key_path);

bool generate_ecdsa_keypair(
    const std::string& curve_name,
    const std::string& private_key_path,
    const std::string& public_key_path);

bool generate_rsa_keypair(
    int bits,
    const std::string& private_key_path,
    const std::string& public_key_path);

bool generate_csr(
    const std::string& private_key_path,
    const std::string& csr_path,
    const std::vector<std::string>& subject_info);

X509_REQ_ptr load_csr(
    const std::string& csr_path);

bool generate_self_signed_certificate(
    const std::string& csr_path,
    const std::string& private_key_path,
    const std::string& certificate_path,
    int days);

// ============================================================================
// EXPORTED C API BLOCK
//
// All LIB_API functions are intentionally placed near the beginning of the
// translation unit.  The implementation below is only a thin C ABI layer.
// Internal C++ methods remain below and continue to use std::string,
// std::vector, RAII unique_ptr wrappers, and OpenSSL EVP/X509 types.
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

    std::vector<std::string> split_subject_string(
        const char* subject_string)
    {
        std::vector<std::string> fields;

        if (!subject_string)
            return fields;

        std::string subject(subject_string);
        size_t start = 0;

        while (true)
        {
            size_t comma = subject.find(',', start);

            if (comma == std::string::npos)
            {
                fields.push_back(subject.substr(start));
                break;
            }

            fields.push_back(subject.substr(start, comma - start));
            start = comma + 1;
        }

        return fields;
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

/*
bool read_file_bytes(
    const std::string& file_path,
    std::vector<unsigned char>& data);
*/
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
        std::vector<unsigned char> buffer;

        if (!read_file_bytes(std::string(file_path), buffer))
        {
            set_last_api_error("read_file_bytes failed in internal C++ implementation.");
            return false;
        }

        if (buffer.empty())
            return true;

        unsigned char* raw = static_cast<unsigned char*>(
            std::malloc(buffer.size()));

        if (!raw)
        {
            set_last_api_error("Out of memory while allocating file buffer.");
            return false;
        }

        std::memcpy(raw, buffer.data(), buffer.size());

        *out_data = raw;
        *out_size = buffer.size();

        return true;
    }
    catch (const std::exception& e)
    {
        set_last_api_error(e.what());
        return false;
    }
    catch (...)
    {
        set_last_api_error("Unknown exception in read_file_bytes.");
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

    if (!data && size != 0)
    {
        set_last_api_error("write_file_bytes received null data with non-zero size.");
        return false;
    }

    try
    {
        std::vector<unsigned char> buffer;

        if (size != 0)
        {
            buffer.assign(data, data + size);
        }

        if (!write_file_bytes(std::string(file_path), buffer))
        {
            set_last_api_error("write_file_bytes failed in internal C++ implementation.");
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

    if (!data && size != 0)
    {
        set_last_api_error("base64_encode received null data with non-zero size.");
        return nullptr;
    }

    try
    {
        if (size == 0)
            return duplicate_c_string(std::string());

        std::vector<unsigned char> buffer(data, data + size);
        std::string encoded = base64_encode(buffer);

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
bool generate_ecdsa_keypair(
    const char* curve_name,
    const char* private_key_path,
    const char* public_key_path) noexcept
{
    clear_last_api_error();

    if (!curve_name || !private_key_path || !public_key_path)
    {
        set_last_api_error(
            "generate_ecdsa_keypair requires non-null curve_name, private_key_path, and public_key_path.");
        return false;
    }

    try
    {
        bool ok = generate_ecdsa_keypair(
            std::string(curve_name),
            std::string(private_key_path),
            std::string(public_key_path));

        if (!ok)
            set_last_api_error("generate_ecdsa_keypair failed in internal C++ implementation.");

        return ok;
    }
    catch (const std::exception& e)
    {
        set_last_api_error(e.what());
        return false;
    }
    catch (...)
    {
        set_last_api_error("Unknown exception in generate_ecdsa_keypair.");
        return false;
    }
}

LIB_API
bool generate_rsa_keypair(
    int bits,
    const char* private_key_path,
    const char* public_key_path) noexcept
{
    clear_last_api_error();

    if (!private_key_path || !public_key_path)
    {
        set_last_api_error(
            "generate_rsa_keypair requires non-null private_key_path and public_key_path.");
        return false;
    }

    try
    {
        bool ok = generate_rsa_keypair(
            bits,
            std::string(private_key_path),
            std::string(public_key_path));

        if (!ok)
            set_last_api_error("generate_rsa_keypair failed in internal C++ implementation.");

        return ok;
    }
    catch (const std::exception& e)
    {
        set_last_api_error(e.what());
        return false;
    }
    catch (...)
    {
        set_last_api_error("Unknown exception in generate_rsa_keypair.");
        return false;
    }
}

LIB_API
bool generate_csr(
    const char* private_key_path,
    const char* csr_path,
    const char* subject_string) noexcept
{
    clear_last_api_error();

    if (!private_key_path || !csr_path || !subject_string)
    {
        set_last_api_error(
            "generate_csr requires non-null private_key_path, csr_path, and subject_string.");
        return false;
    }

    try
    {
        std::vector<std::string> fields = split_subject_string(subject_string);

        if (fields.empty())
        {
            set_last_api_error("generate_csr received an empty subject string.");
            return false;
        }

        bool ok = generate_csr(
            std::string(private_key_path),
            std::string(csr_path),
            fields);

        if (!ok)
            set_last_api_error("generate_csr failed in internal C++ implementation.");

        return ok;
    }
    catch (const std::exception& e)
    {
        set_last_api_error(e.what());
        return false;
    }
    catch (...)
    {
        set_last_api_error("Unknown exception in generate_csr.");
        return false;
    }
}

LIB_API
bool generate_self_signed_certificate(
    const char* csr_path,
    const char* private_key_path,
    const char* certificate_path,
    int days) noexcept
{
    clear_last_api_error();

    if (!csr_path || !private_key_path || !certificate_path)
    {
        set_last_api_error(
            "generate_self_signed_certificate requires non-null csr_path, private_key_path, and certificate_path.");
        return false;
    }

    try
    {
        bool ok = generate_self_signed_certificate(
            std::string(csr_path),
            std::string(private_key_path),
            std::string(certificate_path),
            days);

        if (!ok)
            set_last_api_error(
                "generate_self_signed_certificate failed in internal C++ implementation.");

        return ok;
    }
    catch (const std::exception& e)
    {
        set_last_api_error(e.what());
        return false;
    }
    catch (...)
    {
        set_last_api_error("Unknown exception in generate_self_signed_certificate.");
        return false;
    }
}

// ============================================================================
// OPENSSL ERROR HANDLER
// ============================================================================

void handle_openssl_error(const std::string& context)
{
    std::cerr << "\n[OpenSSL Error] "
              << context
              << "\n";

    ERR_print_errors_fp(stderr);
}

// ============================================================================
// FILE I/O HELPERS
// ============================================================================


// ============================================================================
// DLL EXPORT WRAPPER
// C-compatible API for Python ctypes
// ============================================================================

//Function overload for C-style string input, which converts it to std::string and calls the main function.
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
        std::cerr << "Cannot open file: "
                  << file_path << "\n";

        return false;
    }

    std::streamsize size = file.tellg();

    if (size < 0)
    {
        std::cerr << "Failed to determine file size.\n";
        return false;
    }

    if (size == 0)
    {
        data.clear();
        return true;
    }

    file.seekg(0, std::ios::beg);

    data.resize(static_cast<size_t>(size));

    if (!file.read(
            reinterpret_cast<char*>(data.data()),
            size))
    {
        std::cerr << "Failed to read file.\n";
        return false;
    }

    return true;
}

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
        std::cerr << "Cannot open output file.\n";
        return false;
    }

    if (!data.empty())
    {
        if (!file.write(
                reinterpret_cast<const char*>(data.data()),
                data.size()))
        {
            std::cerr << "Failed to write file.\n";
            return false;
        }
    }

    return true;
}

// ============================================================================
// BASE64 ENCODER
// ============================================================================
//Internal C++ implementation of base64 encoding.

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

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

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

    BIO_get_mem_ptr(b64, &buffer_ptr);

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
        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
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

        return EVP_PKEY_ptr(nullptr, EVP_PKEY_free);
    }

    return EVP_PKEY_ptr(raw_key, EVP_PKEY_free);
}

// ============================================================================
// ECDSA KEY GENERATION
// ============================================================================

bool generate_ecdsa_keypair(
    const std::string& curve_name,
    const std::string& private_key_path,
    const std::string& public_key_path)
{
    EVP_PKEY_CTX_ptr ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr),
        EVP_PKEY_CTX_free
    );

    if (!ctx)
    {
        handle_openssl_error("EVP_PKEY_CTX_new_id");
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
    {
        handle_openssl_error("EVP_PKEY_keygen_init");
        return false;
    }

    int curve_nid = OBJ_txt2nid(curve_name.c_str());

    if (curve_nid == NID_undef)
    {
        std::cerr << "Invalid curve name: "
                  << curve_name << "\n";

        return false;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
            ctx.get(),
            curve_nid) <= 0)
    {
        handle_openssl_error(
            "EVP_PKEY_CTX_set_ec_paramgen_curve_nid");

        return false;
    }

    EVP_PKEY* raw_key = nullptr;

    if (EVP_PKEY_keygen(ctx.get(), &raw_key) <= 0)
    {
        handle_openssl_error("EVP_PKEY_keygen");
        return false;
    }

    EVP_PKEY_ptr key(raw_key, EVP_PKEY_free);

    BIO_ptr priv_bio(
        BIO_new_file(private_key_path.c_str(), "wb"),
        BIO_free_all
    );

    if (!priv_bio)
    {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_PrivateKey(
            priv_bio.get(),
            key.get(),
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr) != 1)
    {
        handle_openssl_error(
            "PEM_write_bio_PrivateKey");

        return false;
    }

    BIO_ptr pub_bio(
        BIO_new_file(public_key_path.c_str(), "wb"),
        BIO_free_all
    );

    if (!pub_bio)
    {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_PUBKEY(
            pub_bio.get(),
            key.get()) != 1)
    {
        handle_openssl_error(
            "PEM_write_bio_PUBKEY");

        return false;
    }

    return true;
}

// ============================================================================
// RSA KEY GENERATION
// ============================================================================


bool generate_rsa_keypair(
    int bits,
    const std::string& private_key_path,
    const std::string& public_key_path)
{
    EVP_PKEY_CTX_ptr ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
        EVP_PKEY_CTX_free
    );

    if (!ctx)
    {
        handle_openssl_error("EVP_PKEY_CTX_new_id");
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
    {
        handle_openssl_error("EVP_PKEY_keygen_init");
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(
            ctx.get(),
            bits) <= 0)
    {
        handle_openssl_error(
            "EVP_PKEY_CTX_set_rsa_keygen_bits");

        return false;
    }

    EVP_PKEY* raw_key = nullptr;

    if (EVP_PKEY_keygen(ctx.get(), &raw_key) <= 0)
    {
        handle_openssl_error("EVP_PKEY_keygen");
        return false;
    }

    EVP_PKEY_ptr key(raw_key, EVP_PKEY_free);

    BIO_ptr priv_bio(
        BIO_new_file(private_key_path.c_str(), "wb"),
        BIO_free_all
    );

    if (!priv_bio)
    {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_PrivateKey(
            priv_bio.get(),
            key.get(),
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr) != 1)
    {
        handle_openssl_error(
            "PEM_write_bio_PrivateKey");

        return false;
    }

    BIO_ptr pub_bio(
        BIO_new_file(public_key_path.c_str(), "wb"),
        BIO_free_all
    );

    if (!pub_bio)
    {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_PUBKEY(
            pub_bio.get(),
            key.get()) != 1)
    {
        handle_openssl_error(
            "PEM_write_bio_PUBKEY");

        return false;
    }

    return true;
}

// ============================================================================
// CSR GENERATION
// ============================================================================


bool generate_csr(
    const std::string& private_key_path,
    const std::string& csr_path,
    const std::vector<std::string>& subject_info)
{
    EVP_PKEY_ptr key =
        load_private_key(private_key_path);

    if (!key)
        return false;

    X509_REQ_ptr req(
        X509_REQ_new(),
        X509_REQ_free
    );

    if (!req)
    {
        handle_openssl_error("X509_REQ_new");
        return false;
    }

    if (X509_REQ_set_version(req.get(), 0L) != 1)
    {
        handle_openssl_error(
            "X509_REQ_set_version");

        return false;
    }

    X509_NAME* name =
        X509_REQ_get_subject_name(req.get());

    if (!name)
    {
        handle_openssl_error(
            "X509_REQ_get_subject_name");

        return false;
    }

    for (const auto& entry : subject_info)
    {
        size_t pos = entry.find('=');

        if (pos == std::string::npos)
        {
            std::cerr << "Invalid subject entry: "
                      << entry << "\n";

            return false;
        }

        std::string field =
            entry.substr(0, pos);

        std::string value =
            entry.substr(pos + 1);

        if (X509_NAME_add_entry_by_txt(
                name,
                field.c_str(),
                MBSTRING_ASC,
                reinterpret_cast<
                    const unsigned char*>(
                        value.c_str()),
                -1,
                -1,
                0) != 1)
        {
            handle_openssl_error(
                "X509_NAME_add_entry_by_txt");

            return false;
        }
    }

    if (X509_REQ_set_pubkey(
            req.get(),
            key.get()) != 1)
    {
        handle_openssl_error(
            "X509_REQ_set_pubkey");

        return false;
    }

    if (X509_REQ_sign(
            req.get(),
            key.get(),
            EVP_sha256()) <= 0)
    {
        handle_openssl_error(
            "X509_REQ_sign");

        return false;
    }

    BIO_ptr csr_bio(
        BIO_new_file(csr_path.c_str(), "wb"),
        BIO_free_all
    );

    if (!csr_bio)
    {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_X509_REQ(
            csr_bio.get(),
            req.get()) != 1)
    {
        handle_openssl_error(
            "PEM_write_bio_X509_REQ");

        return false;
    }

    return true;
}

// ============================================================================
// LOAD CSR
// ============================================================================


//Internal C++ implementation for loading a CSR from a file.
X509_REQ_ptr load_csr(
    const std::string& csr_path)
{
    BIO_ptr csr_bio(
        BIO_new_file(csr_path.c_str(), "rb"),
        BIO_free_all
    );

    if (!csr_bio)
    {
        handle_openssl_error("BIO_new_file");

        return X509_REQ_ptr(
            nullptr,
            X509_REQ_free
        );
    }

    X509_REQ* raw_req =
        PEM_read_bio_X509_REQ(
            csr_bio.get(),
            nullptr,
            nullptr,
            nullptr
        );

    if (!raw_req)
    {
        handle_openssl_error(
            "PEM_read_bio_X509_REQ");

        return X509_REQ_ptr(
            nullptr,
            X509_REQ_free
        );
    }

    return X509_REQ_ptr(
        raw_req,
        X509_REQ_free
    );
}

// ============================================================================
// SELF-SIGNED CERTIFICATE
// ============================================================================

//Internal C++ implementation for generating a self-signed certificate from a CSR and a private key.
bool generate_self_signed_certificate(
    const std::string& csr_path,
    const std::string& private_key_path,
    const std::string& certificate_path,
    int days)
{
    X509_REQ_ptr req =
        load_csr(csr_path);

    if (!req)
        return false;

    EVP_PKEY_ptr ca_key =
        load_private_key(private_key_path);

    if (!ca_key)
        return false;

    EVP_PKEY* raw_pubkey =
        X509_REQ_get_pubkey(req.get());

    if (!raw_pubkey)
    {
        handle_openssl_error(
            "X509_REQ_get_pubkey");

        return false;
    }

    EVP_PKEY_ptr pubkey(
        raw_pubkey,
        EVP_PKEY_free
    );

    if (X509_REQ_verify(
            req.get(),
            pubkey.get()) != 1)
    {
        handle_openssl_error(
            "X509_REQ_verify");

        return false;
    }

    X509_ptr cert(
        X509_new(),
        X509_free
    );

    if (!cert)
    {
        handle_openssl_error("X509_new");
        return false;
    }

    if (X509_set_version(cert.get(), 2L) != 1)
    {
        handle_openssl_error(
            "X509_set_version");

        return false;
    }

    ASN1_INTEGER_ptr serial(
        ASN1_INTEGER_new(),
        ASN1_INTEGER_free
    );

    ASN1_INTEGER_set(serial.get(), 1L);

    X509_set_serialNumber(
        cert.get(),
        serial.get()
    );

    X509_NAME* subject =
        X509_REQ_get_subject_name(req.get());

    X509_set_subject_name(
        cert.get(),
        subject
    );

    X509_set_issuer_name(
        cert.get(),
        subject
    );

    X509_gmtime_adj(
        X509_getm_notBefore(cert.get()),
        0
    );

    X509_gmtime_adj(
        X509_getm_notAfter(cert.get()),
        60L * 60L * 24L * days
    );

    X509_set_pubkey(
        cert.get(),
        pubkey.get()
    );

    if (X509_sign(
            cert.get(),
            ca_key.get(),
            EVP_sha256()) <= 0)
    {
        handle_openssl_error(
            "X509_sign");

        return false;
    }

    BIO_ptr cert_bio(
        BIO_new_file(certificate_path.c_str(), "wb"),
        BIO_free_all
    );

    if (!cert_bio)
    {
        handle_openssl_error("BIO_new_file");
        return false;
    }

    if (PEM_write_bio_X509(
            cert_bio.get(),
            cert.get()) != 1)
    {
        handle_openssl_error(
            "PEM_write_bio_X509");

        return false;
    }

    return true;
}

// ============================================================================
// MAIN
//
// EXCLUDED DURING DLL BUILD
// ============================================================================

#ifndef LIB_EXPORTS

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr
            << "Usage:\n"
            << "  " << argv[0]
            << " ecdsa <curve> <private.pem> <public.pem>\n"

            << "  " << argv[0]
            << " rsa <bits> <private.pem> <public.pem>\n"

            << "  " << argv[0]
            << " csr <private.pem> <csr.pem> <CN=...,O=...>\n"

            << "  " << argv[0]
            << " selfsign <csr.pem> <private.pem> <cert.pem> <days>\n";

        return 1;
    }

    std::string mode = argv[1];

    // ECDSA
    if (mode == "ecdsa")
    {
        if (argc != 5)
        {
            std::cerr << "Invalid arguments.\n";
            return 1;
        }

        return generate_ecdsa_keypair(
            argv[2],
            argv[3],
            argv[4]
        ) ? 0 : 1;
    }

    // RSA
    if (mode == "rsa")
    {
        if (argc != 5)
        {
            std::cerr << "Invalid arguments.\n";
            return 1;
        }

        return generate_rsa_keypair(
            std::stoi(argv[2]),
            argv[3],
            argv[4]
        ) ? 0 : 1;
    }

    // CSR
    if (mode == "csr")
    {
        if (argc != 5)
        {
            std::cerr << "Invalid arguments.\n";
            return 1;
        }

        std::vector<std::string> fields;

        std::string subject = argv[4];

        size_t start = 0;

        while (true)
        {
            size_t comma =
                subject.find(',', start);

            if (comma == std::string::npos)
            {
                fields.push_back(
                    subject.substr(start));

                break;
            }

            fields.push_back(
                subject.substr(
                    start,
                    comma - start));

            start = comma + 1;
        }

        return generate_csr(
            argv[2],
            argv[3],
            fields
        ) ? 0 : 1;
    }

    // Self-signed certificate
    if (mode == "selfsign")
    {
        if (argc != 6)
        {
            std::cerr << "Invalid arguments.\n";
            return 1;
        }

        return generate_self_signed_certificate(
            argv[2],
            argv[3],
            argv[4],
            std::stoi(argv[5])
        ) ? 0 : 1;
    }

    std::cerr << "Unknown command.\n";

    return 1;
}

#endif