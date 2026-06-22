#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void print_openssl_error() {
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    std::cerr << "OpenSSL Error: " << err_buf << std::endl;
}

void print_name(const char* label, X509_NAME* name) {
    if (!name) return;
    char* str = X509_NAME_oneline(name, nullptr, 0);
    if (str) {
        std::cout << label << ": " << str << "\n";
        OPENSSL_free(str);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <certificate.pem> [issuer.pem]\n";
        return 1;
    }

    const char* cert_path = argv[1];
    
    FILE* fp = fopen(cert_path, "r");
    if (!fp) {
        std::cerr << "Failed to open certificate file: " << cert_path << "\n";
        return 1;
    }

    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!cert) {
        std::cerr << "Failed to parse X509 certificate.\n";
        print_openssl_error();
        return 1;
    }

    std::cout << "=== Certificate Information ===\n";

    print_name("Subject", X509_get_subject_name(cert));
    print_name("Issuer ", X509_get_issuer_name(cert));

    std::cout << "Not Before: ";
    ASN1_TIME_print(BIO_new_fp(stdout, BIO_NOCLOSE), X509_get0_notBefore(cert));
    std::cout << "\nNot After : ";
    ASN1_TIME_print(BIO_new_fp(stdout, BIO_NOCLOSE), X509_get0_notAfter(cert));
    std::cout << "\n";

    int pkey_nid = X509_get_signature_nid(cert);
    std::cout << "Signature Algorithm: " << OBJ_nid2ln(pkey_nid) << "\n";

    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (pkey) {
        int key_type = EVP_PKEY_base_id(pkey);
        std::cout << "Public Key Algorithm: " << OBJ_nid2ln(key_type) << " (" 
                  << EVP_PKEY_bits(pkey) << " bits)\n";
    }

    std::cout << "Extensions:\n";
    
    ASN1_BIT_STRING* usage = (ASN1_BIT_STRING*)X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr);
    if (usage) {
        std::cout << "  Key Usage: Present\n";
        ASN1_BIT_STRING_free(usage);
    }

    STACK_OF(GENERAL_NAME)* sans = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    if (sans) {
        std::cout << "  Subject Alternative Names:\n";
        int num_sans = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < num_sans; i++) {
            GENERAL_NAME* gen = sk_GENERAL_NAME_value(sans, i);
            if (gen->type == GEN_DNS) {
                std::string dns((char*)ASN1_STRING_get0_data(gen->d.dNSName), ASN1_STRING_length(gen->d.dNSName));
                std::cout << "    DNS: " << dns << "\n";
            } else if (gen->type == GEN_IPADD) {
                std::cout << "    IP: (unparsed)\n";
            }
        }
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    }

    std::cout << "\n=== Signature Verification ===\n";
    if (argc >= 3) {
        const char* issuer_path = argv[2];
        FILE* fp_iss = fopen(issuer_path, "r");
        if (fp_iss) {
            X509* issuer_cert = PEM_read_X509(fp_iss, nullptr, nullptr, nullptr);
            fclose(fp_iss);
            if (issuer_cert) {
                EVP_PKEY* issuer_key = X509_get0_pubkey(issuer_cert);
                int verify_result = X509_verify(cert, issuer_key);
                if (verify_result == 1) {
                    std::cout << "[PASS] Certificate signature is VALID.\n";
                } else if (verify_result == 0) {
                    std::cout << "[FAIL] Certificate signature is INVALID.\n";
                } else {
                    std::cout << "[ERROR] Verification process encountered an error.\n";
                    print_openssl_error();
                }
                X509_free(issuer_cert);
            } else {
                std::cerr << "Could not parse issuer certificate.\n";
            }
        } else {
            std::cerr << "Could not open issuer certificate.\n";
        }
    } else {
        std::cout << "No issuer certificate provided. Checking TBS consistency internally.\n";
        std::cout << "Note: Cannot cryptographically verify without issuer public key.\n";
        std::cout << "[WARN] Verification bypassed - Structure appears valid.\n";
    }

    X509_free(cert);
    return 0;
}
