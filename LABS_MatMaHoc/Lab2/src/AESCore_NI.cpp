#include "AESCore_NI.h"
#include <cstring>
#include <stdexcept>

namespace AESCore_NI {

bool CheckAESNI() {
#if defined(_MSC_VER)
  int cpuInfo[4];
  __cpuid(cpuInfo, 1);
  return (cpuInfo[2] & (1 << 25)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
  unsigned int eax, ebx, ecx, edx;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    return (ecx & (1 << 25)) != 0;
  }
  return false;
#else
  return false;
#endif
}

AES_NI::AES_NI(const uint8_t *key, size_t keyLen) {
  if (!CheckAESNI()) {
    throw std::runtime_error("CPU does not support AES-NI instructions");
  }

  if (keyLen == 16) {
    Nr = 10;
    KeyExpansion128(key);
  } else if (keyLen == 24) {
    Nr = 12;
    KeyExpansion192(key);
  } else if (keyLen == 32) {
    Nr = 14;
    KeyExpansion256(key);
  } else {
    throw std::invalid_argument(
        "Invalid key length. Must be 16, 24, or 32 bytes.");
  }
}

AES_NI::~AES_NI() {}

static inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
  __m128i temp3;
  temp2 = _mm_shuffle_epi32(temp2, 0xff);
  temp3 = _mm_slli_si128(temp1, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp1 = _mm_xor_si128(temp1, temp2);
  return temp1;
}

void AES_NI::KeyExpansion128(const uint8_t *key) {
  roundKeys.resize(11);
  __m128i temp1, temp2;

  temp1 = _mm_loadu_si128((const __m128i *)key);
  roundKeys[0] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[1] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[2] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[3] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[4] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[5] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[6] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[7] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[8] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[9] = temp1;

  temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
  temp1 = AES_128_ASSIST(temp1, temp2);
  roundKeys[10] = temp1;
}

void AES_NI::KeyExpansion192(const uint8_t *key) {
  throw std::runtime_error(
      "AES-192-NI Key Expansion not fully implemented yet");
}

void AES_NI::KeyExpansion256(const uint8_t *key) {
  throw std::runtime_error(
      "AES-256-NI Key Expansion not fully implemented yet");
}

void AES_NI::EncryptBlock(const uint8_t in[16], uint8_t out[16]) const {
  __m128i m = _mm_loadu_si128((const __m128i *)in);

  m = _mm_xor_si128(m, roundKeys[0]);

  for (int i = 1; i < Nr; i++) {
    m = _mm_aesenc_si128(m, roundKeys[i]);
  }

  m = _mm_aesenclast_si128(m, roundKeys[Nr]);

  _mm_storeu_si128((__m128i *)out, m);
}

} 
