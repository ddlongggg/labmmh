# Save and Load AES Key/IV with Crypto++ (File and Array Pipeline)

This snippet demonstrates how to **generate, save, and load AES key and IV** using the **Crypto++ library** via `FileSink/FileSource` and `ArraySink/ArraySource`.

---

## 🔧 Demo Code

```cpp
#include <iostream>
#include <fstream>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;
using namespace std;

//////////////////////////////////////////////////////////////
// Utility: Print hex
//////////////////////////////////////////////////////////////

void PrintHex(const string& label, const byte* data, size_t len)
{
    string encoded;

    StringSource(data, len, true,
        new HexEncoder(
            new StringSink(encoded),
            false
        )
    );

    cout << label << ": " << encoded << endl;
}

//////////////////////////////////////////////////////////////
// Generate AES Key + IV
//////////////////////////////////////////////////////////////

void GenerateAESKey(SecByteBlock& key, SecByteBlock& iv)
{
    AutoSeededRandomPool prng;

    key.CleanNew(AES::DEFAULT_KEYLENGTH);
    iv.CleanNew(AES::BLOCKSIZE);

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());
}

//////////////////////////////////////////////////////////////
// HEX Save
//////////////////////////////////////////////////////////////

void SaveHex(const string& file,
             const SecByteBlock& key,
             const SecByteBlock& iv)
{
    string keyHex, ivHex;

    StringSource(key, key.size(), true,
        new HexEncoder(new StringSink(keyHex), false));

    StringSource(iv, iv.size(), true,
        new HexEncoder(new StringSink(ivHex), false));

    ofstream out(file);

    if(!out)
        throw runtime_error("Cannot open file for writing");

    out << "KEY=" << keyHex << endl;
    out << "IV=" << ivHex << endl;
}

//////////////////////////////////////////////////////////////
// HEX Load
//////////////////////////////////////////////////////////////

void LoadHex(const string& file,
             SecByteBlock& key,
             SecByteBlock& iv)
{
    ifstream in(file);

    if(!in)
        throw runtime_error("Cannot open file");

    string line1, line2;

    getline(in, line1);
    getline(in, line2);

    if(line1.rfind("KEY=",0)!=0 || line2.rfind("IV=",0)!=0)
        throw runtime_error("Invalid HEX key format");

    string keyHex = line1.substr(4);
    string ivHex  = line2.substr(3);

    key.CleanNew(AES::DEFAULT_KEYLENGTH);
    iv.CleanNew(AES::BLOCKSIZE);

    StringSource(keyHex, true,
        new HexDecoder(
            new ArraySink(key, key.size())
        )
    );

    StringSource(ivHex, true,
        new HexDecoder(
            new ArraySink(iv, iv.size())
        )
    );
}

//////////////////////////////////////////////////////////////
// Binary Save
//////////////////////////////////////////////////////////////

void SaveBinary(const string& file,
                const SecByteBlock& key,
                const SecByteBlock& iv)
{
    FileSink sink(file.c_str());

    sink.Put(key, key.size());
    sink.Put(iv, iv.size());

    sink.MessageEnd();
}

//////////////////////////////////////////////////////////////
// Binary Load
//////////////////////////////////////////////////////////////

void LoadBinary(const string& file,
                SecByteBlock& key,
                SecByteBlock& iv)
{
    key.CleanNew(AES::DEFAULT_KEYLENGTH);
    iv.CleanNew(AES::BLOCKSIZE);

    FileSource src(file.c_str(), true);

    src.Get(key, key.size());
    src.Get(iv, iv.size());
}

//////////////////////////////////////////////////////////////
// Format Dispatcher
//////////////////////////////////////////////////////////////

void SaveKey(const string& format,
             const string& file,
             const SecByteBlock& key,
             const SecByteBlock& iv)
{
    if(format=="hex")
        SaveHex(file,key,iv);

    else if(format=="bin")
        SaveBinary(file,key,iv);

    else
        throw runtime_error("Unknown format");
}

void LoadKey(const string& format,
             const string& file,
             SecByteBlock& key,
             SecByteBlock& iv)
{
    if(format=="hex")
        LoadHex(file,key,iv);

    else if(format=="bin")
        LoadBinary(file,key,iv);

    else
        throw runtime_error("Unknown format");
}

//////////////////////////////////////////////////////////////
// CLI Commands
//////////////////////////////////////////////////////////////

void cmd_generate(const string& format,
                  const string& file)
{
    SecByteBlock key, iv;

    GenerateAESKey(key, iv);

    SaveKey(format,file,key,iv);

    cout << "Key generated and saved to " << file << endl;

    PrintHex("Key", key, key.size());
    PrintHex("IV", iv, iv.size());
}

void cmd_show(const string& format,
              const string& file)
{
    SecByteBlock key, iv;

    LoadKey(format,file,key,iv);

    PrintHex("Key", key, key.size());
    PrintHex("IV", iv, iv.size());
}

void cmd_convert(const string& srcFormat,
                 const string& srcFile,
                 const string& dstFormat,
                 const string& dstFile)
{
    SecByteBlock key, iv;

    LoadKey(srcFormat,srcFile,key,iv);

    SaveKey(dstFormat,dstFile,key,iv);

    cout << "Converted " << srcFile << " -> " << dstFile << endl;
}

//////////////////////////////////////////////////////////////
// Usage
//////////////////////////////////////////////////////////////

void usage()
{
    cout << "AES Key CLI Utility\n\n";

    cout << "Commands:\n";

    cout << "  generate <hex|bin> <file>\n";
    cout << "  show     <hex|bin> <file>\n";
    cout << "  convert  <src_format> <src_file> <dst_format> <dst_file>\n\n";

    cout << "Examples:\n";

    cout << "  aeskey generate hex key.hex\n";
    cout << "  aeskey generate bin key.bin\n";

    cout << "  aeskey show hex key.hex\n";
    cout << "  aeskey show bin key.bin\n";

    cout << "  aeskey convert bin key.bin hex key.hex\n";
}

//////////////////////////////////////////////////////////////
// Main CLI
//////////////////////////////////////////////////////////////

int main(int argc, char* argv[])
{
    if(argc < 2)
    {
        usage();
        return 1;
    }

    string cmd = argv[1];

    try
    {
        if(cmd=="generate")
        {
            if(argc!=4)
                throw runtime_error("Invalid arguments");

            cmd_generate(argv[2],argv[3]);
        }

        else if(cmd=="show")
        {
            if(argc!=4)
                throw runtime_error("Invalid arguments");

            cmd_show(argv[2],argv[3]);
        }

        else if(cmd=="convert")
        {
            if(argc!=6)
                throw runtime_error("Invalid arguments");

            cmd_convert(argv[2],argv[3],argv[4],argv[5]);
        }

        else
        {
            usage();
        }
    }
    catch(const Exception& e)
    {
        cerr << "Crypto++ error: " << e.what() << endl;
    }
    catch(const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}
```

---

## ✅ Summary

| Method       | Save           | Load            |
|--------------|----------------|-----------------|
| **File**     | `FileSink`     | `FileSource`    |
| **Memory**   | `ArraySink`    | `ArraySource`   |

These functions ensure flexible AES key/IV management using **both file-based** and **memory-based** pipelines in Crypto++.
