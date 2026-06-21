#include "CipherCore.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>


#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/modes.h>
#include <cryptopp/xts.h>

using namespace CryptoPP;
using namespace std;

namespace CipherCore {

size_t GetFileSize(const string &filename) {
  ifstream in(filename, ifstream::ate | ifstream::binary);
  if (!in)
    throw runtime_error("Cannot open file: " + filename);
  return in.tellg();
}

template <class MODE>
void EncryptFile(const string &in, const string &out,
                 const CipherOptions &opt) {
  MODE enc;
  if constexpr (is_same_v<MODE, ECB_Mode<AES>::Encryption>) {
    enc.SetKey(opt.key, opt.key.size());
  } else {
    enc.SetKeyWithIV(opt.key, opt.key.size(), opt.iv);
  }

  FileSource fs(in.c_str(), true,
                new StreamTransformationFilter(
                    enc, new FileSink(out.c_str()),
                    opt.noPadding
                        ? StreamTransformationFilter::NO_PADDING
                        : StreamTransformationFilter::DEFAULT_PADDING));
}

template <class MODE>
void DecryptFile(const string &in, const string &out,
                 const CipherOptions &opt) {
  MODE dec;
  if constexpr (is_same_v<MODE, ECB_Mode<AES>::Decryption>) {
    dec.SetKey(opt.key, opt.key.size());
  } else {
    dec.SetKeyWithIV(opt.key, opt.key.size(), opt.iv);
  }

  FileSource fs(in.c_str(), true,
                new StreamTransformationFilter(
                    dec, new FileSink(out.c_str()),
                    opt.noPadding
                        ? StreamTransformationFilter::NO_PADDING
                        : StreamTransformationFilter::DEFAULT_PADDING));
}

template <class AEAD_MODE>
void EncryptAEAD(const string &in, const string &out, const CipherOptions &opt,
                 SecByteBlock &outTag) {
  AEAD_MODE enc;
  enc.SetKeyWithIV(opt.key, opt.key.size(), opt.iv, opt.iv.size());

  const int TAG_SIZE = 16;
  outTag.CleanNew(TAG_SIZE);

  if (!enc.IsValidKeyLength(opt.key.size())) {
    throw runtime_error("Invalid key length for AEAD");
  }

  ifstream inFileStream(in, ios::binary | ios::ate);
  size_t fileSize = inFileStream.tellg();
  inFileStream.seekg(0);

  enc.SpecifyDataLengths(opt.aad.size(), fileSize, 0);

  if (opt.aad.size() > 0) {
    enc.Update((const CryptoPP::byte *)opt.aad.data(), opt.aad.size());
  }

  ofstream outFileStream(out, ios::binary);
  const size_t BUFFER_SIZE = 4096;
  CryptoPP::byte inBuffer[BUFFER_SIZE];
  CryptoPP::byte outBuffer[BUFFER_SIZE];

  while (inFileStream.read((char*)inBuffer, BUFFER_SIZE) || inFileStream.gcount() > 0) {
      size_t count = inFileStream.gcount();
      enc.ProcessData(outBuffer, inBuffer, count);
      outFileStream.write((char*)outBuffer, count);
  }

  enc.TruncatedFinal(outTag.data(), TAG_SIZE);
}

template <class AEAD_MODE>
void DecryptAEAD(const string &in, const string &out, const CipherOptions &opt,
                 const SecByteBlock &inTag) {
  AEAD_MODE dec;
  dec.SetKeyWithIV(opt.key, opt.key.size(), opt.iv, opt.iv.size());

  const int TAG_SIZE = 16;
  if (inTag.size() != TAG_SIZE)
    throw runtime_error("Invalid Tag Size for AEAD");

  ifstream inFileStream(in, ios::binary | ios::ate);
  size_t fileSize = inFileStream.tellg();
  inFileStream.seekg(0);

  dec.SpecifyDataLengths(opt.aad.size(), fileSize, 0);

  if (opt.aad.size() > 0) {
    dec.Update((const CryptoPP::byte *)opt.aad.data(), opt.aad.size());
  }

  ofstream outFileStream(out, ios::binary);
  const size_t BUFFER_SIZE = 4096;
  CryptoPP::byte inBuffer[BUFFER_SIZE];
  CryptoPP::byte outBuffer[BUFFER_SIZE];

  while (inFileStream.read((char*)inBuffer, BUFFER_SIZE) || inFileStream.gcount() > 0) {
      size_t count = inFileStream.gcount();
      dec.ProcessData(outBuffer, inBuffer, count);
      outFileStream.write((char*)outBuffer, count);
  }

  if (!dec.TruncatedVerify(inTag.data(), inTag.size())) {
      throw runtime_error("HashVerificationFilter: message hash or MAC not valid");
  }
}

void Encrypt(const string &inFile, const string &outFile,
             const CipherOptions &opt, SecByteBlock &outTag) {
  if (opt.mode == "ecb") {
    cout << "WARNING: ECB mode is insecure and should not be used." << endl;
    if (GetFileSize(inFile) > 16384 && !opt.allowEcb) {
      throw runtime_error(
          "File size > 16 KiB. ECB blocked. Use --allow-ecb to override.");
    }
    EncryptFile<ECB_Mode<AES>::Encryption>(inFile, outFile, opt);
  } else if (opt.mode == "cbc") {
    EncryptFile<CBC_Mode<AES>::Encryption>(inFile, outFile, opt);
  } else if (opt.mode == "ofb") {
    EncryptFile<OFB_Mode<AES>::Encryption>(inFile, outFile, opt);
  } else if (opt.mode == "cfb") {
    EncryptFile<CFB_Mode<AES>::Encryption>(inFile, outFile, opt);
  } else if (opt.mode == "ctr") {
    EncryptFile<CTR_Mode<AES>::Encryption>(inFile, outFile, opt);
  } else if (opt.mode == "xts") {
    if (opt.key.size() != 32 && opt.key.size() != 64) {
      throw runtime_error(
          "XTS mode requires exactly 32 or 64 byte key (2x standard size).");
    }
    EncryptFile<XTS_Mode<AES>::Encryption>(inFile, outFile, opt);
  } else if (opt.mode == "gcm") {
    if (!opt.isAead)
      throw runtime_error("GCM is an AEAD mode. Use --aead flag.");
    EncryptAEAD<GCM<AES>::Encryption>(inFile, outFile, opt, outTag);
  } else if (opt.mode == "ccm") {
    if (!opt.isAead)
      throw runtime_error("CCM is an AEAD mode. Use --aead flag.");
    EncryptAEAD<CCM<AES>::Encryption>(inFile, outFile, opt, outTag);
  } else {
    throw runtime_error("Unsupported AES mode: " + opt.mode);
  }
}

void Decrypt(const string &inFile, const string &outFile,
             const CipherOptions &opt, const SecByteBlock &inTag) {
  if (opt.mode == "ecb") {
    DecryptFile<ECB_Mode<AES>::Decryption>(inFile, outFile, opt);
  } else if (opt.mode == "cbc") {
    DecryptFile<CBC_Mode<AES>::Decryption>(inFile, outFile, opt);
  } else if (opt.mode == "ofb") {
    DecryptFile<OFB_Mode<AES>::Decryption>(inFile, outFile, opt);
  } else if (opt.mode == "cfb") {
    DecryptFile<CFB_Mode<AES>::Decryption>(inFile, outFile, opt);
  } else if (opt.mode == "ctr") {
    DecryptFile<CTR_Mode<AES>::Decryption>(inFile, outFile, opt);
  } else if (opt.mode == "xts") {
    DecryptFile<XTS_Mode<AES>::Decryption>(inFile, outFile, opt);
  } else if (opt.mode == "gcm") {
    if (!opt.isAead)
      throw runtime_error("GCM is an AEAD mode. Use --aead flag.");
    DecryptAEAD<GCM<AES>::Decryption>(inFile, outFile, opt, inTag);
  } else if (opt.mode == "ccm") {
    if (!opt.isAead)
      throw runtime_error("CCM is an AEAD mode. Use --aead flag.");
    DecryptAEAD<CCM<AES>::Decryption>(inFile, outFile, opt, inTag);
  } else {
    throw runtime_error("Unsupported AES mode: " + opt.mode);
  }
}

} // namespace CipherCore
