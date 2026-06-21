# Guide 1: ASN.1 Syntax and Key Format for RSA Cryptography
Task requireds.
+) Gen RSA key use OpenSSL
# Generate key
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:3072
# Extract public key
openssl rsa -in private.pem -pubout -out public.pem

# Convert PEM → DER
openssl rsa -in private.pem -outform DER -out private.der
openssl pkey -pubin -in public.pem -outform DER -out public.der

+) Manual extract all elements in keys

Dump ASN.1
openssl asn1parse -in public.der -inform DER
openssl asn1parse -in private.der -inform DER

Identify Structure Layers
SEQUENCE (SPKI)
 ├── SEQUENCE (AlgorithmIdentifier)
 │    ├── OID = 1.2.840.113549.1.1.1
 │    └── NULL
 └── BIT STRING
      └── SEQUENCE (RSAPublicKey)
           ├── INTEGER → n
           └── INTEGER → e

SEQUENCE (PKCS#8)
 ├── version
 ├── AlgorithmIdentifier
 └── OCTET STRING
      └── SEQUENCE (RSAPrivateKey)
           ├── n
           ├── e
           ├── d
           ├── p
           ├── q
           ├── dP
           ├── dQ
           ├── qInv

Manualy extract ALL RSA Parameters
n (modulus)
e (public exponent)

n
e
d
p
q
dP = d mod (p-1)
dQ = d mod (q-1)
qInv = q⁻¹ mod p

### Required Output Format
[PUBLIC KEY]
n (hex) = ...
e (dec) = 65537

[PRIVATE KEY]
n (hex) = ...
e (dec) = 65537
d (hex) = ...
p (hex) = ...
q (hex) = ...
dP (hex) = ...
dQ (hex) = ...
qInv (hex) = ...

## Introduction

This guide provides a comprehensive overview of ASN.1 syntax and key formats used in RSA cryptography, with a focus on implementation using the Crypto++ library. Understanding these concepts is essential for working with RSA keys, certificates, and cryptographic operations in a secure and interoperable manner.

## What is ASN.1?

ASN.1 (Abstract Syntax Notation One) is a standard interface description language for defining data structures that can be serialized and deserialized in a cross-platform way. It's widely used in telecommunications and computer networking, particularly in cryptography for representing keys, certificates, and other security-related data.

Key characteristics of ASN.1:

- Platform-independent notation for describing data structures
- Separates the data structure definition from its encoding
- Provides rules for encoding data in a binary format
- Enables interoperability between different systems and programming languages

## ASN.1 Encoding Rules

ASN.1 defines several encoding rules, but the most commonly used in cryptography are:

1. **BER (Basic Encoding Rules)** - The original encoding rules, which allow some flexibility in how data is encoded.
2. **DER (Distinguished Encoding Rules)** - A subset of BER that ensures a unique encoding for each ASN.1 value, making it suitable for cryptographic applications where bit-exact comparisons are important.

In cryptography, DER is typically used for writing keys and certificates, while BER is used for reading them. This follows the principle of "write strict, read loose" to promote interoperability.

## Key Formats in RSA Cryptography

RSA keys can be stored in various formats, each with its own structure and purpose:

### 1. PKCS#1 Format

PKCS#1 (Public-Key Cryptography Standards #1) is specific to RSA keys.

#### RSA Private Key (PKCS#1)

```
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

#### RSA Public Key (PKCS#1)

```
RSAPublicKey ::= SEQUENCE {
  modulus           INTEGER,  -- n
  publicExponent    INTEGER   -- e
}
```

### 2. PKCS#8 Format

PKCS#8 is a more generic format that can handle different types of keys, not just RSA.

#### Private Key (PKCS#8)

```
PrivateKeyInfo ::= SEQUENCE {
  version           Version,
  algorithm         AlgorithmIdentifier,
  privateKey        OCTET STRING
}

AlgorithmIdentifier ::= SEQUENCE {
  algorithm         OBJECT IDENTIFIER,
  parameters        ANY DEFINED BY algorithm OPTIONAL
}
```

For RSA private keys, the OID is `1.2.840.113549.1.1.1`, and the `privateKey` field contains the DER-encoded RSA private key structure.

#### Public Key (PKCS#8, also known as X.509 SubjectPublicKeyInfo)

```
PublicKeyInfo ::= SEQUENCE {
  algorithm         AlgorithmIdentifier,
  publicKey         BIT STRING
}

AlgorithmIdentifier ::= SEQUENCE {
  algorithm         OBJECT IDENTIFIER,
  parameters        ANY DEFINED BY algorithm OPTIONAL
}
```

For RSA public keys, the OID is `1.2.840.113549.1.1.1`, and the `publicKey` field contains the DER-encoded RSA public key structure.

## Binary vs. Text Representation

RSA keys can be stored in two main forms:

### 1. DER (Distinguished Encoding Rules)

DER is a binary format that directly represents the ASN.1 structure. It's compact but not human-readable.

+--------+--------+-------------------+
| Tag    | Length | Value             |
+--------+--------+-------------------+
Length: 
short form
0..
Long form (N bytes):
0x80 + N(bytes)
0x82 --> 0x80+ 2 ==> N=2
Tag: Identifies the type (e.g., INTEGER = 0x02, SEQUENCE = 0x30, BIT STRING = 0x03, etc.)
https://en.wikipedia.org/wiki/X.690

certutil -dump rsa-pubkey.der
1. 30 82 02 22
•	30 = SEQUENCE
•	82 02 22 = Length = 0x0222 = 546 bytes
o	This is the full wrapper: the SubjectPublicKeyInfo structure.
________________________________________
2. 30 0D
•	Inner SEQUENCE (algorithm identifier)
•	Length: 0x0D = 13 bytes
________________________________________
3. Inside the algorithm identifier:
a. 06 09 2A864886F70D010101
•	06 = OBJECT IDENTIFIER
•	Length = 09 bytes
•	Value = 2A 86 48 86 F7 0D 01 01 01 = 1.2.840.113549.1.1.1 → RSA Encryption
b. 05 00
•	05 = NULL
•	Length = 0 (no value)
•	This completes the algorithm identifier.
________________________________________
4. 03 82 02 0F 00
•	03 = BIT STRING (used for the public key)
•	Length = 0x020F = 527 bytes
•	The next 00 byte = unused bits count (always 0 for key data)
________________________________________
5. 30 82 02 0A
•	Another SEQUENCE inside the BIT STRING
•	Length = 0x020A = 522 bytes
•	This holds the RSAPublicKey structure.
________________________________________
6. Inside the RSAPublicKey SEQUENCE:
a. 02 82 02 01 <modulus>
•	02 = INTEGER (modulus n)
•	Length = 0x0201 = 513 bytes
•	This is your RSA modulus (n) – a huge integer.
b. 02 03 01 00 01
•	02 = INTEGER (exponent e)
•	Length = 3 bytes
•	Value = 01 00 01 = 65537 (standard RSA public exponent)



Length: Length of value bytes. If >127, it's prefixed with a byte indicating the length of the length.

Value: The actual data content

### 2. PEM (Privacy-Enhanced Mail)

PEM is a base64-encoded version of DER with header and footer lines that indicate the type of data contained. It's designed to be human-readable and easily transmitted through text-based channels.

Example of a PEM-encoded RSA public key:

```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMYfnvWtC8Id5bPKae5yXSxQTt
+Zpul6AnnZWfI2TtIarvjHBFUtXRo96y7hoL4VWOPKGCsRqMFDkrbeUjRrx8iL91
4/srnyf6sh9c8Zk04xEOpK1ypvBz+Ks4uZObtjnnitf0NBGdjMKxveTq+VE7BWUI
yQjtQ8mbDOsiLLvh7wIDAQAB
-----END PUBLIC KEY-----
```

PEM files use different header/footer tags to indicate the type of key:

- `-----BEGIN RSA PRIVATE KEY-----` / `-----END RSA PRIVATE KEY-----` for PKCS#1 RSA private keys
- `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----` for PKCS#8 unencrypted private keys
- `-----BEGIN ENCRYPTED PRIVATE KEY-----` / `-----END ENCRYPTED PRIVATE KEY-----` for PKCS#8 encrypted private keys
- `-----BEGIN RSA PUBLIC KEY-----` / `-----END RSA PUBLIC KEY-----` for PKCS#1 RSA public keys
- `-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----` for PKCS#8 public keys

## Crypto++ and Key Formats

Crypto++ uses specific classes to handle different key formats:

### Key Classes in Crypto++

1. **RSA::PrivateKey** and **RSA::PublicKey** - The main classes for RSA keys
2. **PKCS8PrivateKey** - Base class for private keys that can be loaded/saved in PKCS#8 format
3. **X509PublicKey** - Base class for public keys that can be loaded/saved in X.509 format

### Key Format Handling in Crypto++

Crypto++ provides methods to load and save keys in standard formats:

```cpp
// For private keys
void RSA::PrivateKey::Load(BufferedTransformation &bt);
void RSA::PrivateKey::Save(BufferedTransformation &bt) const;

// For public keys
void RSA::PublicKey::Load(BufferedTransformation &bt);
void RSA::PublicKey::Save(BufferedTransformation &bt) const;
```

These methods work with PKCS#8 for private keys and X.509 SubjectPublicKeyInfo for public keys.

## Converting Between Formats

### DER to PEM Conversion

To convert a DER-encoded key to PEM format:
1. Base64 encode the DER data
2. Add appropriate header and footer
3. Insert line breaks every 64 characters

### PEM to DER Conversion

To convert a PEM-encoded key to DER format:
1. Remove header, footer, and line breaks
2. Base64 decode the remaining data

## Important Considerations

1. **Security**: Private keys should be stored securely, preferably encrypted when at rest.
2. **Compatibility**: Use standard formats (PKCS#8, X.509) for maximum interoperability with other libraries and systems.
3. **Validation**: Always validate keys after loading them to ensure they are well-formed and meet security requirements.
4. **Key Size**: Modern RSA keys should be at least 2048 bits (preferably 3072 bits) to provide adequate security.

## Conclusion

Understanding ASN.1 syntax and key formats is crucial for working with RSA cryptography. The Crypto++ library provides robust support for standard formats, making it easier to create interoperable cryptographic applications.

In the next guide, we'll explore how to generate RSA keys using the Crypto++ library and save them in both PEM and DER formats.
