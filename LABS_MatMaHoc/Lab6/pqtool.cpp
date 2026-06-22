#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>

using namespace std;

int print_errors_cb(const char *str, size_t len, void *u) {
    cerr << str;
    return 1;
}

void print_errors() {
    ERR_print_errors_cb(print_errors_cb, NULL);
}

vector<uint8_t> read_file(const string& path) {
    ifstream file(path, ios::binary | ios::ate);
    if (!file) throw runtime_error("Cannot open file " + path);
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    vector<uint8_t> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size))
        return buffer;
    throw runtime_error("Error reading file " + path);
}

void write_file(const string& path, const vector<uint8_t>& data) {
    ofstream file(path, ios::binary);
    if (!file) throw runtime_error("Cannot create file " + path);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

EVP_PKEY* read_pubkey(const string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (!bio) throw runtime_error("Cannot open public key " + path);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        print_errors();
        throw runtime_error("Failed to read public key");
    }
    return pkey;
}

EVP_PKEY* read_privkey(const string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (!bio) throw runtime_error("Cannot open private key " + path);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        print_errors();
        throw runtime_error("Failed to read private key");
    }
    return pkey;
}

string map_algo(const string& algo) {
    if (algo == "mldsa-44") return "ML-DSA-44";
    if (algo == "mldsa-65") return "ML-DSA-65";
    if (algo == "mlkem-512") return "ML-KEM-512";
    if (algo == "mlkem-768") return "ML-KEM-768";
    return algo;
}

void do_keygen(const string& algo, const string& pub_path, const string& priv_path) {
    string ossl_algo = map_algo(algo);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, ossl_algo.c_str(), NULL);
    if (!ctx) { print_errors(); throw runtime_error("Context creation failed for " + ossl_algo); }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) { print_errors(); throw runtime_error("Keygen init failed"); }
    
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { print_errors(); throw runtime_error("Keygen failed"); }
    
    BIO* bio_priv = BIO_new_file(priv_path.c_str(), "wb");
    if (!bio_priv || !PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL)) {
        if (bio_priv) BIO_free(bio_priv);
        throw runtime_error("Failed to write private key");
    }
    BIO_free(bio_priv);
    
    BIO* bio_pub = BIO_new_file(pub_path.c_str(), "wb");
    if (!bio_pub || !PEM_write_bio_PUBKEY(bio_pub, pkey)) {
        if (bio_pub) BIO_free(bio_pub);
        throw runtime_error("Failed to write public key");
    }
    BIO_free(bio_pub);
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    cout << "Successfully generated " << ossl_algo << " key pair." << endl;
}

void do_sign(const string& algo, const string& in_path, const string& out_path, const string& priv_path) {
    EVP_PKEY* pkey = read_privkey(priv_path);
    vector<uint8_t> msg = read_file(in_path);
    
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
        print_errors();
        throw runtime_error("Sign init failed");
    }
    
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx, NULL, &sig_len, msg.data(), msg.size()) <= 0) {
        print_errors();
        throw runtime_error("Sign size query failed");
    }
    
    vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(md_ctx, sig.data(), &sig_len, msg.data(), msg.size()) <= 0) {
        print_errors();
        throw runtime_error("Sign failed");
    }
    sig.resize(sig_len);
    
    write_file(out_path, sig);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    cout << "Successfully signed. Signature saved to " << out_path << endl;
}

void do_verify(const string& algo, const string& in_path, const string& sig_path, const string& pub_path) {
    EVP_PKEY* pkey = read_pubkey(pub_path);
    vector<uint8_t> msg = read_file(in_path);
    vector<uint8_t> sig = read_file(sig_path);
    
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit_ex(md_ctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
        print_errors();
        throw runtime_error("Verify init failed");
    }
    
    if (EVP_DigestVerify(md_ctx, sig.data(), sig.size(), msg.data(), msg.size()) <= 0) {
        print_errors();
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        throw runtime_error("Signature verification failed!");
    }
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    cout << "Signature verified successfully." << endl;
}

void do_encaps(const string& algo, const string& pub_path, const string& ct_path, const string& ss_path) {
    EVP_PKEY* pkey = read_pubkey(pub_path);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    
    if (!ctx || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        print_errors();
        throw runtime_error("Encapsulate init failed");
    }
    
    size_t outlen = 0, secretlen = 0;
    if (EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &secretlen) <= 0) {
        print_errors();
        throw runtime_error("Encapsulate size query failed");
    }
    
    vector<uint8_t> ct(outlen);
    vector<uint8_t> ss(secretlen);
    
    if (EVP_PKEY_encapsulate(ctx, ct.data(), &outlen, ss.data(), &secretlen) <= 0) {
        print_errors();
        throw runtime_error("Encapsulate failed");
    }
    ct.resize(outlen);
    ss.resize(secretlen);
    
    write_file(ct_path, ct);
    write_file(ss_path, ss);
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    cout << "Successfully encapsulated. Shared secret size: " << secretlen << " bytes." << endl;
}

void do_decaps(const string& algo, const string& priv_path, const string& ct_path, const string& ss_path) {
    EVP_PKEY* pkey = read_privkey(priv_path);
    vector<uint8_t> ct = read_file(ct_path);
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!ctx || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) {
        print_errors();
        throw runtime_error("Decapsulate init failed");
    }
    
    size_t secretlen = 0;
    if (EVP_PKEY_decapsulate(ctx, NULL, &secretlen, ct.data(), ct.size()) <= 0) {
        print_errors();
        throw runtime_error("Decapsulate size query failed");
    }
    
    vector<uint8_t> ss(secretlen);
    if (EVP_PKEY_decapsulate(ctx, ss.data(), &secretlen, ct.data(), ct.size()) <= 0) {
        print_errors();
        throw runtime_error("Decapsulation failed (possibly tampered ciphertext)");
    }
    ss.resize(secretlen);
    
    write_file(ss_path, ss);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    cout << "Successfully decapsulated. Shared secret size: " << secretlen << " bytes." << endl;
}

string get_arg(int argc, char** argv, const string& flag) {
    for (int i = 1; i < argc - 1; ++i) {
        if (string(argv[i]) == flag) return argv[i+1];
    }
    return "";
}

int main(int argc, char** argv) {
    OSSL_PROVIDER* prov = OSSL_PROVIDER_load(NULL, "default");
    if (!prov) {
        cerr << "Failed to load default provider" << endl;
        print_errors();
    }
    
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <cmd> [args]" << endl;
        if (prov) OSSL_PROVIDER_unload(prov);
        return 1;
    }
    
    string cmd = argv[1];
    
    try {
        if (cmd == "keygen") {
            string algo = get_arg(argc, argv, "--algo");
            string pub = get_arg(argc, argv, "--pub");
            string priv = get_arg(argc, argv, "--priv");
            if (algo.empty() || pub.empty() || priv.empty()) throw runtime_error("Missing args for keygen");
            do_keygen(algo, pub, priv);
        } else if (cmd == "sign") {
            string algo = get_arg(argc, argv, "--algo");
            string in = get_arg(argc, argv, "--in");
            string out = get_arg(argc, argv, "--out");
            string priv = get_arg(argc, argv, "--priv");
            if (priv.empty()) priv = "priv.pem";
            if (algo.empty() || in.empty() || out.empty()) throw runtime_error("Missing args for sign");
            do_sign(algo, in, out, priv);
        } else if (cmd == "verify") {
            string algo = get_arg(argc, argv, "--algo");
            string in = get_arg(argc, argv, "--in");
            string sig = get_arg(argc, argv, "--sig");
            string pub = get_arg(argc, argv, "--pub");
            if (algo.empty() || in.empty() || sig.empty() || pub.empty()) throw runtime_error("Missing args for verify");
            do_verify(algo, in, sig, pub);
        } else if (cmd == "encaps") {
            string algo = get_arg(argc, argv, "--algo");
            string pub = get_arg(argc, argv, "--pub");
            string ct = get_arg(argc, argv, "--ct");
            string ss = get_arg(argc, argv, "--ss");
            if (algo.empty() || pub.empty() || ct.empty() || ss.empty()) throw runtime_error("Missing args for encaps");
            do_encaps(algo, pub, ct, ss);
        } else if (cmd == "decaps") {
            string algo = get_arg(argc, argv, "--algo");
            string priv = get_arg(argc, argv, "--priv");
            string ct = get_arg(argc, argv, "--ct");
            string ss = get_arg(argc, argv, "--ss");
            if (algo.empty() || priv.empty() || ct.empty() || ss.empty()) throw runtime_error("Missing args for decaps");
            do_decaps(algo, priv, ct, ss);
        } else {
            throw runtime_error("Unknown command: " + cmd);
        }
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        if (prov) OSSL_PROVIDER_unload(prov);
        return 1;
    }
    
    if (prov) OSSL_PROVIDER_unload(prov);
    return 0;
}
