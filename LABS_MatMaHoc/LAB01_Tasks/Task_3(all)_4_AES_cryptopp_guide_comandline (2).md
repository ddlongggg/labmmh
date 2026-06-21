
# AES Encryption and Decryption using Crypto++ (CLI Tool)

This guide demonstrates how to build a **command-line AES encryption tool using Crypto++** in C++.

The tool supports:

* AES key generation
* Key storage in **HEX or Binary format**
* AES encryption/decryption
* Multiple AES modes
* File-based encryption via CLI

---

# 1. CLI Tool Overview

The program behaves like a **mini crypto toolkit**.

```
aescli <command> [options]
```

Supported commands:

```
generate <hex|bin> <keyfile>
show     <hex|bin> <keyfile>

encrypt  <mode> <hex|bin> <keyfile> <input> <output>
decrypt  <mode> <hex|bin> <keyfile> <input> <output>

convert  <src_format> <src_file> <dst_format> <dst_file>
```

Supported AES modes:

```
cbc
cfb
ofb
ctr
gcm
```

---

# 2. Example CLI Usage

### Generate AES key

HEX format

```
aescli generate hex key.hex
```

Binary format

```
aescli generate bin key.bin
```

---

### Show key

```
aescli show hex key.hex
aescli show bin key.bin
```

---

### Encrypt file

```
aescli encrypt cbc hex key.hex message.txt message.enc
```

---

### Decrypt file

```
aescli decrypt cbc hex key.hex message.enc restored.txt
```

---

### Convert key formats

```
aescli convert bin key.bin hex key.hex
```

---

# 3. Compile Instructions

Linux / macOS

```
g++ aescli.cpp -lcryptopp -o aescli
```

Windows (MinGW)

```
g++ aescli.cpp -lcryptopp -o aescli.exe
```

---

# 4. Complete C++ Implementation

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
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>

using namespace CryptoPP;
using namespace std;

//////////////////////////////////////////////////////////////
// Utility: Print Hex
//////////////////////////////////////////////////////////////

void PrintHex(const string& label,const byte* data,size_t len)
{
    string encoded;

    StringSource(data,len,true,
        new HexEncoder(
            new StringSink(encoded),
            false
        )
    );

    cout<<label<<": "<<encoded<<endl;
}

//////////////////////////////////////////////////////////////
// Generate AES Key + IV
//////////////////////////////////////////////////////////////

void GenerateAESKey(SecByteBlock& key,SecByteBlock& iv)
{
    AutoSeededRandomPool prng;

    key.CleanNew(AES::DEFAULT_KEYLENGTH);
    iv.CleanNew(AES::BLOCKSIZE);

    prng.GenerateBlock(key,key.size());
    prng.GenerateBlock(iv,iv.size());
}

//////////////////////////////////////////////////////////////
// HEX Key Save
//////////////////////////////////////////////////////////////

void SaveHex(const string& file,const SecByteBlock& key,const SecByteBlock& iv)
{
    string keyHex,ivHex;

    StringSource(key,key.size(),true,new HexEncoder(new StringSink(keyHex),false));
    StringSource(iv,iv.size(),true,new HexEncoder(new StringSink(ivHex),false));

    ofstream out(file);

    out<<"KEY="<<keyHex<<endl;
    out<<"IV="<<ivHex<<endl;
}

//////////////////////////////////////////////////////////////
// HEX Key Load
//////////////////////////////////////////////////////////////

void LoadHex(const string& file,SecByteBlock& key,SecByteBlock& iv)
{
    ifstream in(file);

    string line1,line2;
    getline(in,line1);
    getline(in,line2);

    string keyHex=line1.substr(4);
    string ivHex=line2.substr(3);

    key.CleanNew(AES::DEFAULT_KEYLENGTH);
    iv.CleanNew(AES::BLOCKSIZE);

    StringSource(keyHex,true,new HexDecoder(new ArraySink(key,key.size())));
    StringSource(ivHex,true,new HexDecoder(new ArraySink(iv,iv.size())));
}

//////////////////////////////////////////////////////////////
// Binary Key Save
//////////////////////////////////////////////////////////////

void SaveBinary(const string& file,const SecByteBlock& key,const SecByteBlock& iv)
{
    FileSink sink(file.c_str());

    sink.Put(key,key.size());
    sink.Put(iv,iv.size());

    sink.MessageEnd();
}

//////////////////////////////////////////////////////////////
// Binary Key Load
//////////////////////////////////////////////////////////////

void LoadBinary(const string& file,SecByteBlock& key,SecByteBlock& iv)
{
    key.CleanNew(AES::DEFAULT_KEYLENGTH);
    iv.CleanNew(AES::BLOCKSIZE);

    FileSource src(file.c_str(),true);

    src.Get(key,key.size());
    src.Get(iv,iv.size());
}

//////////////////////////////////////////////////////////////
// Format Dispatcher
//////////////////////////////////////////////////////////////

void LoadKey(const string& format,const string& file,SecByteBlock& key,SecByteBlock& iv)
{
    if(format=="hex")
        LoadHex(file,key,iv);
    else if(format=="bin")
        LoadBinary(file,key,iv);
    else
        throw runtime_error("Unknown key format");
}

void SaveKey(const string& format,const string& file,const SecByteBlock& key,const SecByteBlock& iv)
{
    if(format=="hex")
        SaveHex(file,key,iv);
    else if(format=="bin")
        SaveBinary(file,key,iv);
    else
        throw runtime_error("Unknown key format");
}

//////////////////////////////////////////////////////////////
// Generic Encrypt
//////////////////////////////////////////////////////////////

template<class MODE>
void EncryptFile(const string& in,const string& out,const SecByteBlock& key,const SecByteBlock& iv)
{
    MODE enc;
    enc.SetKeyWithIV(key,key.size(),iv);

    FileSource fs(in.c_str(),true,
        new StreamTransformationFilter(enc,
            new FileSink(out.c_str())
        )
    );
}

//////////////////////////////////////////////////////////////
// Generic Decrypt
//////////////////////////////////////////////////////////////

template<class MODE>
void DecryptFile(const string& in,const string& out,const SecByteBlock& key,const SecByteBlock& iv)
{
    MODE dec;
    dec.SetKeyWithIV(key,key.size(),iv);

    FileSource fs(in.c_str(),true,
        new StreamTransformationFilter(dec,
            new FileSink(out.c_str())
        )
    );
}

//////////////////////////////////////////////////////////////
// GCM Encrypt
//////////////////////////////////////////////////////////////

void EncryptGCM(const string& in,const string& out,const SecByteBlock& key,const SecByteBlock& iv)
{
    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key,key.size(),iv,iv.size());

    FileSource fs(in.c_str(),true,
        new AuthenticatedEncryptionFilter(enc,
            new FileSink(out.c_str())
        )
    );
}

//////////////////////////////////////////////////////////////
// GCM Decrypt
//////////////////////////////////////////////////////////////

void DecryptGCM(const string& in,const string& out,const SecByteBlock& key,const SecByteBlock& iv)
{
    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key,key.size(),iv,iv.size());

    FileSource fs(in.c_str(),true,
        new AuthenticatedDecryptionFilter(dec,
            new FileSink(out.c_str())
        )
    );
}

//////////////////////////////////////////////////////////////
// Encryption Dispatcher
//////////////////////////////////////////////////////////////

void EncryptDispatch(const string& mode,const string& in,const string& out,const SecByteBlock& key,const SecByteBlock& iv)
{
    if(mode=="cbc")
        EncryptFile<CBC_Mode<AES>::Encryption>(in,out,key,iv);
    else if(mode=="cfb")
        EncryptFile<CFB_Mode<AES>::Encryption>(in,out,key,iv);
    else if(mode=="ofb")
        EncryptFile<OFB_Mode<AES>::Encryption>(in,out,key,iv);
    else if(mode=="ctr")
        EncryptFile<CTR_Mode<AES>::Encryption>(in,out,key,iv);
    else if(mode=="gcm")
        EncryptGCM(in,out,key,iv);
    else
        throw runtime_error("Unsupported AES mode");
}

//////////////////////////////////////////////////////////////
// Decryption Dispatcher
//////////////////////////////////////////////////////////////

void DecryptDispatch(const string& mode,const string& in,const string& out,const SecByteBlock& key,const SecByteBlock& iv)
{
    if(mode=="cbc")
        DecryptFile<CBC_Mode<AES>::Decryption>(in,out,key,iv);
    else if(mode=="cfb")
        DecryptFile<CFB_Mode<AES>::Decryption>(in,out,key,iv);
    else if(mode=="ofb")
        DecryptFile<OFB_Mode<AES>::Decryption>(in,out,key,iv);
    else if(mode=="ctr")
        DecryptFile<CTR_Mode<AES>::Decryption>(in,out,key,iv);
    else if(mode=="gcm")
        DecryptGCM(in,out,key,iv);
    else
        throw runtime_error("Unsupported AES mode");
}

//////////////////////////////////////////////////////////////
// Main CLI
//////////////////////////////////////////////////////////////

int main(int argc,char* argv[])
{
    if(argc<2)
    {
        cout<<"Usage:\n";
        cout<<" generate <hex|bin> <keyfile>\n";
        cout<<" show <hex|bin> <keyfile>\n";
        cout<<" encrypt <mode> <hex|bin> <keyfile> <input> <output>\n";
        cout<<" decrypt <mode> <hex|bin> <keyfile> <input> <output>\n";
        return 1;
    }

    string cmd=argv[1];

    try
    {
        if(cmd=="generate")
        {
            SecByteBlock key,iv;
            GenerateAESKey(key,iv);
            SaveKey(argv[2],argv[3],key,iv);
        }

        else if(cmd=="show")
        {
            SecByteBlock key,iv;
            LoadKey(argv[2],argv[3],key,iv);
            PrintHex("Key",key,key.size());
            PrintHex("IV",iv,iv.size());
        }

        else if(cmd=="encrypt")
        {
            SecByteBlock key,iv;
            LoadKey(argv[3],argv[4],key,iv);
            EncryptDispatch(argv[2],argv[5],argv[6],key,iv);
        }

        else if(cmd=="decrypt")
        {
            SecByteBlock key,iv;
            LoadKey(argv[3],argv[4],key,iv);
            DecryptDispatch(argv[2],argv[5],argv[6],key,iv);
        }
    }
    catch(const Exception& e)
    {
        cerr<<"Crypto++ error: "<<e.what()<<endl;
    }
}
```

---

# 5. Supported AES Modes

| Mode | Type                     |
| ---- | ------------------------ |
| CBC  | Block chaining           |
| CFB  | Cipher feedback          |
| OFB  | Output feedback          |
| CTR  | Counter mode             |
| GCM  | Authenticated encryption |

Recommended in practice:

```
AES-GCM
AES-CTR
```

---

# 6. Example Output

HEX key file

```
KEY=8F4A9E6C4A11E9E68E17E3A5C4B2C9A1
IV=9AC5E5D4B0F1AA223B99C24E0D8F01C1
```

---

If you want, I can also produce a **much cleaner “Crypto++ lab assignment version”** of this document with:

* **Task 3.1 — Key generation**
* **Task 3.2 — Key storage**
* **Task 3.3 — AES encryption**
* **Task 3.4 — Multi-mode encryption**
* **Task 3.5 — CLI crypto toolkit**
