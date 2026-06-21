#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include "rsa_keygen.h"
#include "rsa_encrypt.h"
#include "rsa_decrypt.h"
#include "benchmarker.h"

void PrintUsage() {
    std::cout << "Usage:\n"
              << "  rsatool keygen --bits <size> --pub <pub.pem> --priv <priv.pem>\n"
              << "  rsatool encrypt --in <msg.bin> --pub <pub.pem> --out <ct.bin> [--label <optional>]\n"
              << "  rsatool decrypt --in <ct.bin> --priv <priv.pem> --out <msg.bin> [--label <optional>]\n"
              << "  rsatool benchmark\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string command = argv[1];
    std::vector<std::string> args(argv + 2, argv + argc);

    try {
        if (command == "keygen") {
            int bits = 3072;
            std::string pubFile, privFile;
            for (size_t i = 0; i < args.size(); ++i) {
                if (args[i] == "--bits" && i + 1 < args.size()) bits = std::stoi(args[++i]);
                else if (args[i] == "--pub" && i + 1 < args.size()) pubFile = args[++i];
                else if (args[i] == "--priv" && i + 1 < args.size()) privFile = args[++i];
            }
            if (pubFile.empty() || privFile.empty()) {
                std::cerr << "Error: --pub and --priv are required for keygen\n";
                return 1;
            }
            RSA_KeyGen::GenerateKeys(bits, pubFile, privFile);
        }
        else if (command == "encrypt") {
            std::string inFile, pubFile, outFile, label;
            for (size_t i = 0; i < args.size(); ++i) {
                if (args[i] == "--in" && i + 1 < args.size()) inFile = args[++i];
                else if (args[i] == "--pub" && i + 1 < args.size()) pubFile = args[++i];
                else if (args[i] == "--out" && i + 1 < args.size()) outFile = args[++i];
                else if (args[i] == "--label" && i + 1 < args.size()) label = args[++i];
            }
            if (inFile.empty() || pubFile.empty() || outFile.empty()) {
                std::cerr << "Error: --in, --pub, and --out are required for encrypt\n";
                return 1;
            }
            RSA_Encrypt::EncryptFile(inFile, pubFile, outFile, label);
        }
        else if (command == "decrypt") {
            std::string inFile, privFile, outFile, label;
            for (size_t i = 0; i < args.size(); ++i) {
                if (args[i] == "--in" && i + 1 < args.size()) inFile = args[++i];
                else if (args[i] == "--priv" && i + 1 < args.size()) privFile = args[++i];
                else if (args[i] == "--out" && i + 1 < args.size()) outFile = args[++i];
                else if (args[i] == "--label" && i + 1 < args.size()) label = args[++i];
            }
            if (inFile.empty() || privFile.empty() || outFile.empty()) {
                std::cerr << "Error: --in, --priv, and --out are required for decrypt\n";
                return 1;
            }
            RSA_Decrypt::DecryptFile(inFile, privFile, outFile, label);
        }
        else if (command == "benchmark") {
            Benchmarker::RunAllBenchmarks();
        }
        else {
            std::cerr << "Unknown command: " << command << "\n";
            PrintUsage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }

    return 0;
}
