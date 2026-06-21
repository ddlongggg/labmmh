#include "Benchmarker.h"
#include "AESCore.h"
#include "AESCore_NI.h"
#include "AES_CTR.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>

using namespace std;

namespace Benchmarker {

void RunBenchForKeySize(int keySize, const vector<uint8_t> &payload, int runs,
                        int operations, vector<double> &timings) {
  vector<uint8_t> key(keySize, 0x00);
  vector<uint8_t> iv(16, 0x00);

  vector<uint8_t> outBuffer(payload.size());

  // 1. Warm-up (1 second)
  auto warm_start = chrono::high_resolution_clock::now();
  while (true) {
    AESCore::AES aes(key.data(), keySize);
    AES_CTR::ProcessBuffer(aes, iv.data(), payload.data(), outBuffer.data(),
                           payload.size());
    auto now = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = now - warm_start;
    if (diff.count() >= 1.0)
      break;
  }

  // 2 & 3. Execute block of operations, repeat 'runs' times
  for (int r = 0; r < runs; ++r) {
    auto start = chrono::high_resolution_clock::now();

    for (int i = 0; i < operations; ++i) {
      AESCore::AES aes(key.data(), keySize);
      AES_CTR::ProcessBuffer(aes, iv.data(), payload.data(), outBuffer.data(),
                             payload.size());
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = end - start;
    timings.push_back(diff.count());
  }
}

void RunBenchForKeySize_NI(int keySize, const vector<uint8_t> &payload, int runs,
                           int operations, vector<double> &timings) {
  if (!AESCore_NI::CheckAESNI()) {
      cout << "AES-NI not supported on this CPU, skipping...\n";
      for(int i=0; i<runs; i++) timings.push_back(0.0);
      return;
  }
  vector<uint8_t> key(keySize, 0x00);
  vector<uint8_t> iv(16, 0x00);

  vector<uint8_t> outBuffer(payload.size());

  // 1. Warm-up (1 second)
  auto warm_start = chrono::high_resolution_clock::now();
  while (true) {
    AESCore_NI::AES_NI aes(key.data(), keySize);
    AES_CTR::ProcessBuffer(aes, iv.data(), payload.data(), outBuffer.data(),
                           payload.size());
    auto now = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = now - warm_start;
    if (diff.count() >= 1.0)
      break;
  }

  // 2 & 3. Execute block of operations, repeat 'runs' times
  for (int r = 0; r < runs; ++r) {
    auto start = chrono::high_resolution_clock::now();

    for (int i = 0; i < operations; ++i) {
      AESCore_NI::AES_NI aes(key.data(), keySize);
      AES_CTR::ProcessBuffer(aes, iv.data(), payload.data(), outBuffer.data(),
                             payload.size());
    }

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = end - start;
    timings.push_back(diff.count());
  }
}

void RunBenchmark(const string &inFile, const string &csvOutFile, int runs) {
  vector<string> modes = {"aes128", "aes128-ni", "aes192", "aes256"};
  map<string, vector<double>> results;

  // Load payload into memory
  ifstream f(inFile, ios::binary | ios::ate);
  if (!f)
    throw runtime_error("Cannot open payload file");
  size_t size = f.tellg();
  f.seekg(0);
  vector<uint8_t> payload(size);
  f.read((char *)payload.data(), size);
  f.close();

  // User requested ~10 ops
  int operations = 10;

  cout << "Benchmarking AES-128 (" << runs << " runs of " << operations << " ops)...\n";
  RunBenchForKeySize(16, payload, runs, operations, results["aes128"]);

  cout << "Benchmarking AES-128-NI (" << runs << " runs of " << operations << " ops)...\n";
  RunBenchForKeySize_NI(16, payload, runs, operations, results["aes128-ni"]);

  cout << "Benchmarking AES-192 (" << runs << " runs of " << operations << " ops)...\n";
  RunBenchForKeySize(24, payload, runs, operations, results["aes192"]);

  cout << "Benchmarking AES-256 (" << runs << " runs of " << operations << " ops)...\n";
  RunBenchForKeySize(32, payload, runs, operations, results["aes256"]);

  // Write CSV
  ofstream csv(csvOutFile);
  csv << "Run";
  for (const string &mode : modes)
    csv << "," << mode;
  csv << "\n";

  for (int i = 0; i < runs; ++i) {
    csv << i;
    for (const string &mode : modes) {
      csv << "," << results[mode][i];
    }
    csv << "\n";
  }

  cout << "Benchmark complete. Saved to " << csvOutFile << endl;
}
} // namespace Benchmarker
