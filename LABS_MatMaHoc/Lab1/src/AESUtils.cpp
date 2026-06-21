#include "AESUtils.h"
#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include "json.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <filesystem>

using json = nlohmann::json;

using namespace CryptoPP;
using namespace std;

namespace AESUtils {

void PrintHex(const string &label, const CryptoPP::byte *data, size_t len) {
  string encoded;
  StringSource((const CryptoPP::byte *)data, len, true,
               new HexEncoder(new StringSink(encoded), false));
  cout << label << ": " << encoded << endl;
}

void GenerateAESKey(SecByteBlock &key, SecByteBlock &iv, size_t keySize) {
  AutoSeededRandomPool prng;
  key.CleanNew(keySize);
  iv.CleanNew(AES::BLOCKSIZE);
  prng.GenerateBlock(key, key.size());
  prng.GenerateBlock(iv, iv.size());
}

static void SaveHex(const string &file, const SecByteBlock &key,
                    const SecByteBlock &iv) {
  string keyHex, ivHex;
  StringSource(key, key.size(), true,
               new HexEncoder(new StringSink(keyHex), false));
  StringSource(iv, iv.size(), true,
               new HexEncoder(new StringSink(ivHex), false));

  ofstream out(file);
  if (!out)
    throw runtime_error("Cannot open file for writing: " + file);
  out << "KEY=" << keyHex << endl;
  out << "IV=" << ivHex << endl;
}

static void LoadHex(const string &file, SecByteBlock &key, SecByteBlock &iv) {
  ifstream in(file);
  if (!in)
    throw runtime_error("Cannot open file: " + file);
  string line1, line2;
  getline(in, line1);
  getline(in, line2);

  if (line1.rfind("KEY=", 0) != 0 || line2.rfind("IV=", 0) != 0)
    throw runtime_error("Invalid HEX key format in file: " + file);

  string keyHex = line1.substr(4);
  string ivHex = line2.substr(3);

  key.CleanNew(keyHex.size() / 2); // Dynamic based on key read
  iv.CleanNew(AES::BLOCKSIZE);

  StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));
  StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));
}

static void SaveBinary(const string &file, const SecByteBlock &key,
                       const SecByteBlock &iv) {
  FileSink sink(file.c_str());
  sink.Put(key, key.size());
  sink.Put(iv, iv.size());
  sink.MessageEnd();
}

static void LoadBinary(const string &file, SecByteBlock &key,
                       SecByteBlock &iv) {
  // Assume key size is file size - iv size. We can peek size.
  ifstream in(file, ios::binary | ios::ate);
  if (!in)
    throw runtime_error("Cannot open file: " + file);
  size_t fileSize = in.tellg();
  in.close();

  if (fileSize < AES::BLOCKSIZE) {
    throw runtime_error("Invalid key length");
  }

  size_t keySize = fileSize - AES::BLOCKSIZE;
  if (keySize != 16 && keySize != 24 && keySize != 32 && keySize != 64) {
    throw runtime_error("Invalid key length");
  }

  key.CleanNew(keySize);
  iv.CleanNew(AES::BLOCKSIZE);

  FileSource src(file.c_str(), true);
  src.Get(key, key.size());
  src.Get(iv, iv.size());
}

void SaveKey(KeyFormat format, const string &file, const SecByteBlock &key,
             const SecByteBlock &iv) {
  if (format == KeyFormat::HEX)
    SaveHex(file, key, iv);
  else
    SaveBinary(file, key, iv);
}

void LoadKey(KeyFormat format, const string &file, SecByteBlock &key,
             SecByteBlock &iv) {
  if (format == KeyFormat::HEX)
    LoadHex(file, key, iv);
  else
    LoadBinary(file, key, iv);
}

void SaveSidecar(const string &file, const string &alg, const string &mode,
                 const SecByteBlock &iv, const string &aad,
                 const SecByteBlock &tag) {
  ofstream out(file);
  if (!out)
    return;

  out << "{" << endl;
  out << "  \"alg\": \"" << alg << "\"," << endl;
  out << "  \"mode\": \"" << mode << "\"," << endl;

  string ivHex;
  if (iv.size() > 0) {
    StringSource(iv, iv.size(), true,
                 new HexEncoder(new StringSink(ivHex), false));
    out << "  \"iv\": \"" << ivHex << "\"," << endl;
  }

  if (!aad.empty()) {
    out << "  \"aad\": \"" << aad << "\"," << endl;
  }

  if (tag.size() > 0) {
    string tagHex;
    StringSource(tag, tag.size(), true,
                 new HexEncoder(new StringSink(tagHex), false));
    out << "  \"tag\": \"" << tagHex << "\"" << endl;
  }

  out << "}" << endl;
}

void CheckAndRecordNonce(const string& mode, const SecByteBlock& key, const SecByteBlock& iv) {
    if (mode != "ctr" && mode != "ccm" && mode != "gcm") return;
    
    string keyHex, ivHex;
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(keyHex), false));
    StringSource(iv, iv.size(), true, new HexEncoder(new StringSink(ivHex), false));
    string identifier = mode + "_" + keyHex + "_" + ivHex;
    
    string dbFile = "nonce_db.json";
    json db;
    if (std::filesystem::exists(dbFile)) {
        ifstream in(dbFile);
        if(in) in >> db;
    }
    
    if (db.contains(identifier)) {
        throw runtime_error("CATASTROPHIC: Nonce reuse detected for mode " + mode + ". Rejecting operation.");
    }
    
    db[identifier] = true;
    ofstream out(dbFile);
    out << db.dump(4);
}

} // namespace AESUtils
