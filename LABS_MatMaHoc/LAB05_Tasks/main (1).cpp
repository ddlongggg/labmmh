// src/main.cpp
#include "../include/crypto_lib.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>

void print_usage() {
    std::cerr << "Usage: crypto_tool <command> [options]" << std::endl;
    std::cerr << "Commands & Options:" << std::endl;
    std::cerr << "  --gen-ecdsa <curve> <privkey_out> <pubkey_out>" << std::endl;
    std::cerr << "      Example: --gen-ecdsa prime256v1 ecdsa_priv.pem ecdsa_pub.pem" << std::endl;
    std::cerr << "  --gen-rsa <bits> <privkey_out> <pubkey_out>" << std::endl;
    std::cerr << "      Example: --gen-rsa 2048 rsa_priv.pem rsa_pub.pem" << std::endl;
    std::cerr << "  --gen-csr <privkey_in> <csr_out> <subj_C> <subj_ST> <subj_O> <subj_CN>" << std::endl;
    std::cerr << "      Example: --gen-csr rsa_priv.pem server.csr US CA MyOrg localhost" << std::endl;
    std::cerr << "  --gen-cert <csr_in> <privkey_in> <cert_out> <days>" << std::endl;
    std::cerr << "      Example: --gen-cert server.csr rsa_priv.pem server.crt 365" << std::endl;
    std::cerr << "  --sign-ecdsa <privkey_in> <message_in> <signature_out>" << std::endl;
    std::cerr << "      Example: --sign-ecdsa ecdsa_priv.pem message.txt message.ecdsa.sig" << std::endl;
    std::cerr << "  --sign-rsapss <privkey_in> <message_in> <signature_out>" << std::endl;
    std::cerr << "      Example: --sign-rsapss rsa_priv.pem message.txt message.rsapss.sig" << std::endl;
    std::cerr << "  --verify-ecdsa <pubkey_in> <message_in> <signature_in>" << std::endl;
    std::cerr << "      Example: --verify-ecdsa ecdsa_pub.pem message.txt message.ecdsa.sig" << std::endl;
    std::cerr << "  --verify-rsapss <pubkey_in> <message_in> <signature_in>" << std::endl;
    std::cerr << "      Example: --verify-rsapss rsa_pub.pem message.txt message.rsapss.sig" << std::endl;
    std::cerr << "  --extract-pubkey <cert_in> <pubkey_out>" << std::endl;
    std::cerr << "      Example: --extract-pubkey server.crt cert_pubkey.pem" << std::endl;
    std::cerr << "  --verify-cert <cert_in> <message_in> <signature_in>" << std::endl;
    std::cerr << "      Example: --verify-cert server.crt message.txt message.rsapss.sig" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string command = argv[1];
    bool success = false;

    try {
        if (command == "--gen-ecdsa" && argc == 5) {
            success = generate_ecdsa_keypair(argv[2], argv[3], argv[4]);
        } else if (command == "--gen-rsa" && argc == 5) {
            int bits = std::stoi(argv[2]);
            success = generate_rsa_keypair(bits, argv[3], argv[4]);
        } else if (command == "--gen-csr" && argc >= 7) { // >= 7 allows for multiple OUs etc if needed, basic example uses 7
             std::vector<std::string> subject_info;
             // Basic subject: C, ST, O, CN
             if (argc == 8) { // C=, ST=, O=, CN=
                subject_info.push_back("C=" + std::string(argv[4]));
                subject_info.push_back("ST=" + std::string(argv[5]));
                subject_info.push_back("O=" + std::string(argv[6]));
                subject_info.push_back("CN=" + std::string(argv[7]));
             } else {
                 std::cerr << "Error: Incorrect number of subject components for CSR." << std::endl;
                 print_usage();
                 return 1;
             }
             success = generate_csr(argv[2], argv[3], subject_info);
        } else if (command == "--gen-cert" && argc == 6) {
            int days = std::stoi(argv[5]);
            success = generate_self_signed_certificate(argv[2], argv[3], argv[4], days);
        } else if (command == "--sign-ecdsa" && argc == 5) {
            success = sign_ecdsa(argv[2], argv[3], argv[4]);
        } else if (command == "--sign-rsapss" && argc == 5) {
            success = sign_rsapss(argv[2], argv[3], argv[4]);
        } else if (command == "--verify-ecdsa" && argc == 5) {
            success = verify_ecdsa(argv[2], argv[3], argv[4]);
            if (success) {
                std::cout << "ECDSA Verification Successful." << std::endl;
            } else {
                // Error message printed within verify_ecdsa
            }
            // Don't print generic success/failure message for verify
            return success ? 0 : 1;
        } else if (command == "--verify-rsapss" && argc == 5) {
            success = verify_rsapss(argv[2], argv[3], argv[4]);
             if (success) {
                std::cout << "RSASSA-PSS Verification Successful." << std::endl;
            } else {
                // Error message printed within verify_rsapss
            }
            // Don't print generic success/failure message for verify
            return success ? 0 : 1;
        } else if (command == "--extract-pubkey" && argc == 4) {
            success = extract_pubkey_from_cert(argv[2], argv[3]);
        } else if (command == "--verify-cert" && argc == 5) {
            success = verify_signature_with_cert(argv[2], argv[3], argv[4]);
             if (success) {
                std::cout << "Certificate-based Verification Successful." << std::endl;
            } else {
                 // Error message printed within verify_signature_with_cert
            }
            // Don't print generic success/failure message for verify
            return success ? 0 : 1;
        } else {
            std::cerr << "Error: Unknown command or incorrect number of arguments for " << command << std::endl;
            print_usage();
            return 1;
        }
    } catch (const std::invalid_argument& e) {
        std::cerr << "Error: Invalid numeric argument provided: " << e.what() << std::endl;
        return 1;
    } catch (const std::out_of_range& e) {
        std::cerr << "Error: Numeric argument out of range: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "An unknown error occurred." << std::endl;
        return 1;
    }

    if (success) {
        std::cout << "Operation \"" << command << "\" completed successfully." << std::endl;
        return 0;
    } else {
        std::cerr << "Operation \"" << command << "\" failed." << std::endl;
        // Specific errors should have been printed by the functions or handle_openssl_error
        return 1;
    }
}

