#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstdint>
#include <sstream>


#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

class CustomSHA256 {
public:
    uint32_t state[8];
    uint64_t total_len; 
    std::vector<uint8_t> buffer;

    CustomSHA256() {
        state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
        state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
        total_len = 0;
    }

    // Set state from a known hash
    void set_state(const std::vector<uint32_t>& external_state, uint64_t prev_len_bytes) {
        for (int i = 0; i < 8; ++i) state[i] = external_state[i];
        total_len = prev_len_bytes;
        buffer.clear();
    }

    void transform(const uint8_t* block) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t temp1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
            uint32_t temp2 = EP0(a) + MAJ(a, b, c);
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void update(const std::vector<uint8_t>& data) {
        for (uint8_t b : data) {
            buffer.push_back(b);
            if (buffer.size() == 64) {
                transform(buffer.data());
                total_len += 64;
                buffer.clear();
            }
        }
    }

    std::vector<uint8_t> finalize() {
        uint64_t bit_len = (total_len + buffer.size()) * 8;
        buffer.push_back(0x80);
        while (buffer.size() % 64 != 56) {
            buffer.push_back(0x00);
        }
        for (int i = 7; i >= 0; --i) {
            buffer.push_back((bit_len >> (i * 8)) & 0xFF);
        }
        transform(buffer.data());

        std::vector<uint8_t> digest(32);
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = state[i] & 0xFF;
        }
        return digest;
    }
};

std::vector<uint8_t> generate_padding(uint64_t msg_len_bytes) {
    std::vector<uint8_t> pad;
    uint64_t bit_len = msg_len_bytes * 8;
    pad.push_back(0x80);
    uint64_t current_len = msg_len_bytes + 1;
    while (current_len % 64 != 56) {
        pad.push_back(0x00);
        current_len++;
    }
    for (int i = 7; i >= 0; --i) {
        pad.push_back((bit_len >> (i * 8)) & 0xFF);
    }
    return pad;
}

std::vector<uint32_t> parse_hex_hash(const std::string& hex_hash) {
    std::vector<uint32_t> state(8);
    if (hex_hash.length() != 64) throw std::runtime_error("Invalid SHA256 hex length");
    for (int i = 0; i < 8; ++i) {
        state[i] = std::stoul(hex_hash.substr(i * 8, 8), nullptr, 16);
    }
    return state;
}

void print_hex(const std::vector<uint8_t>& data) {
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::cout << std::dec;
}

int main(int argc, char* argv[]) {
    std::cout << "--- SHA-256 Length Extension Demo ---\n";

    std::string secret = "SuperSecretKey!"; 
    std::string msg = "transfer 100$ to Bob";
    
    CustomSHA256 original_hasher;
    std::vector<uint8_t> orig_data(secret.begin(), secret.end());
    orig_data.insert(orig_data.end(), msg.begin(), msg.end());
    original_hasher.update(orig_data);
    std::vector<uint8_t> orig_mac = original_hasher.finalize();

    std::cout << "Secret length : " << secret.length() << " bytes\n";
    std::cout << "Original Msg  : " << msg << "\n";
    std::cout << "Original MAC  : "; print_hex(orig_mac); std::cout << "\n\n";

    std::string append_msg = "; transfer 1000000$ to Eve";
    std::cout << "Target: Append -> " << append_msg << "\n";

    uint64_t known_total_orig_len = secret.length() + msg.length();
    std::vector<uint8_t> padding = generate_padding(known_total_orig_len);

    CustomSHA256 malicious_hasher;
    
    std::vector<uint32_t> malicious_state(8);
    for (int i = 0; i < 8; ++i) {
        malicious_state[i] = (orig_mac[i*4] << 24) | (orig_mac[i*4+1] << 16) | (orig_mac[i*4+2] << 8) | orig_mac[i*4+3];
    }

    uint64_t forged_len_before_append = known_total_orig_len + padding.size();
    
    malicious_hasher.set_state(malicious_state, forged_len_before_append);

    std::vector<uint8_t> append_data(append_msg.begin(), append_msg.end());
    malicious_hasher.update(append_data);
    
    std::vector<uint8_t> forged_mac = malicious_hasher.finalize();

    std::cout << "Forged MAC    : "; print_hex(forged_mac); std::cout << "\n\n";

    std::cout << "Verifying forgery...\n";
    
    std::vector<uint8_t> server_verification_data(secret.begin(), secret.end());
    server_verification_data.insert(server_verification_data.end(), msg.begin(), msg.end());
    server_verification_data.insert(server_verification_data.end(), padding.begin(), padding.end());
    server_verification_data.insert(server_verification_data.end(), append_msg.begin(), append_msg.end());

    CustomSHA256 verify_hasher;
    verify_hasher.update(server_verification_data);
    std::vector<uint8_t> verify_mac = verify_hasher.finalize();

    std::cout << "Server calcs  : "; print_hex(verify_mac); std::cout << "\n";

    if (forged_mac == verify_mac) {
        std::cout << "[SUCCESS] Length extension forgery matches server calculation!\n";
    } else {
        std::cout << "[FAIL] Forgery did not match.\n";
    }

    return 0;
}
