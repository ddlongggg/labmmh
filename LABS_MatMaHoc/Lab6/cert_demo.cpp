#include <iostream>
#include <fstream>
#include <vector>
#include <string>
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

string base64_encode(const vector<uint8_t>& data) {
    int expected_len = 4 * ((data.size() + 2) / 3) + 1;
    vector<uint8_t> out(expected_len);
    int len = EVP_EncodeBlock(out.data(), data.data(), data.size());
    return string(out.begin(), out.begin() + len);
}

vector<uint8_t> base64_decode(const string& b64) {
    int expected_len = 3 * b64.size() / 4;
    vector<uint8_t> out(expected_len);
    int len = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(b64.data()), b64.size());
    if (len < 0) throw runtime_error("Base64 decode failed");
    
    // EVP_DecodeBlock pads with 0s if length isn't mod 4, adjust length
    int pad = 0;
    if (b64.size() > 0 && b64[b64.size() - 1] == '=') pad++;
    if (b64.size() > 1 && b64[b64.size() - 2] == '=') pad++;
    out.resize(len - pad);
    return out;
}

EVP_PKEY* generate_key(const char* algo) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, algo, NULL);
    if (!ctx) { print_errors(); throw runtime_error(string("Keygen ctx creation failed for ") + algo); }
    if (EVP_PKEY_keygen_init(ctx) <= 0) { print_errors(); throw runtime_error("Keygen init failed"); }
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { print_errors(); throw runtime_error("Keygen failed"); }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

string export_pubkey(EVP_PKEY* pkey) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    string res(data, len);
    BIO_free(bio);
    return res;
}

vector<uint8_t> sign_data(EVP_PKEY* privkey, const string& data) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, NULL, privkey, NULL);
    size_t sig_len = 0;
    EVP_DigestSign(md_ctx, NULL, &sig_len, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    vector<uint8_t> sig(sig_len);
    EVP_DigestSign(md_ctx, sig.data(), &sig_len, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    sig.resize(sig_len);
    EVP_MD_CTX_free(md_ctx);
    return sig;
}

bool verify_data(EVP_PKEY* pubkey, const string& data, const vector<uint8_t>& sig) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit_ex(md_ctx, NULL, NULL, NULL, NULL, pubkey, NULL);
    int res = EVP_DigestVerify(md_ctx, sig.data(), sig.size(), reinterpret_cast<const unsigned char*>(data.data()), data.size());
    EVP_MD_CTX_free(md_ctx);
    return res == 1;
}

int main() {
    OSSL_PROVIDER* prov = OSSL_PROVIDER_load(NULL, "default");
    if (!prov) {
        cerr << "Failed to load default provider" << endl;
        print_errors();
    }
    try {
        cout << "1. Generating PQ-CA Key Pair (ML-DSA-44)..." << endl;
        EVP_PKEY* ca_key = generate_key("ML-DSA-44");
        
        cout << "2. Generating Subject Key Pair (ML-DSA-44)..." << endl;
        EVP_PKEY* sub_key = generate_key("ML-DSA-44");
        
        string subject_pub = export_pubkey(sub_key);
        
        // Prepare data to sign (everything except signature)
        string tbs_cert = "{\n  \"subject\": \"Alice\",\n  \"public_key\": \"";
        
        tbs_cert += base64_encode(vector<uint8_t>(subject_pub.begin(), subject_pub.end()));
        tbs_cert += "\",\n  \"issuer\": \"PQ-CA\"\n}";
        
        cout << "\n--- TBS Certificate (To Be Signed) ---\n" << tbs_cert << "\n--------------------------------------\n";
        
        cout << "3. CA signs the TBS Certificate..." << endl;
        vector<uint8_t> sig = sign_data(ca_key, tbs_cert);
        
        string full_cert = tbs_cert;
        // Strip last brace to append signature
        full_cert = full_cert.substr(0, full_cert.size() - 1);
        full_cert += ",\n  \"signature\": \"" + base64_encode(sig) + "\"\n}";
        
        cout << "\n--- Final Certificate ---\n" << full_cert << "\n-------------------------\n\n";
        
        cout << "4. Verifying Certificate Signature..." << endl;
        bool valid = verify_data(ca_key, tbs_cert, sig);
        if (valid) cout << "[PASS] Certificate signature is valid!" << endl;
        else cout << "[FAIL] Certificate signature is invalid!" << endl;
        
        cout << "5. Simulating Tampering (Modifying Subject Name)..." << endl;
        string tampered_tbs = tbs_cert;
        tampered_tbs[tampered_tbs.find("Alice")] = 'M'; 
        
        bool tampered_valid = verify_data(ca_key, tampered_tbs, sig);
        if (!tampered_valid) cout << "[PASS] Tampering detected! Signature verification failed." << endl;
        else cout << "[FAIL] Tampering NOT detected!" << endl;
        
        EVP_PKEY_free(ca_key);
        EVP_PKEY_free(sub_key);
        if (prov) OSSL_PROVIDER_unload(prov);
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        print_errors();
        if (prov) OSSL_PROVIDER_unload(prov);
        return 1;
    }
    
    return 0;
}
