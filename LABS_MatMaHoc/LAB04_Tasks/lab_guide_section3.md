## 3. Cryptanalysis of Hash Functions

While cryptographic hash functions are designed to be secure, they are not infallible. Understanding the potential weaknesses and attack vectors against hash functions is crucial for appreciating the importance of choosing strong algorithms and implementing them correctly. This section explores common cryptanalytic techniques targeting hash functions, specifically focusing on collision attacks and length extension attacks. We will examine the theoretical basis of these attacks and demonstrate practical methods for exploiting vulnerabilities in algorithms like MD5 and, to some extent, SHA-1.

### 3.1 Introduction to Hash Function Attacks

Cryptanalysis of hash functions aims to break one or more of the fundamental security properties: pre-image resistance, second pre-image resistance, or collision resistance. The motivation behind these attacks varies, ranging from forging digital signatures and creating malicious software that bypasses integrity checks to compromising authentication protocols. A successful attack can undermine the security guarantees provided by systems relying on the compromised hash function. The most commonly discussed attacks include finding collisions (two different inputs producing the same hash), finding a pre-image (finding an input that produces a given hash), and exploiting structural properties like those leading to length extension attacks.

### 3.2 Collision Attacks

A collision attack aims to find two distinct inputs, M1 and M2, such that hash(M1) = hash(M2). Finding *any* such pair violates the collision resistance property. The impact of a collision can be severe. For example, if an attacker can create two different documents (one benign, one malicious) that share the same hash value, they might trick someone into signing the benign document, while later substituting the malicious one, which would still validate against the original signature. The feasibility of finding collisions depends heavily on the algorithm's strength and the available computational power. The "Birthday Paradox" in probability theory implies that collisions can typically be found much faster than brute-forcing pre-images.

**MD5 Collisions:** The MD5 algorithm, developed in 1991, is known to be severely broken concerning collision resistance. Practical collision attacks against MD5 have been demonstrated since 2004. It is now computationally inexpensive to generate MD5 collisions. Due to these vulnerabilities, MD5 is considered insecure for applications requiring collision resistance, such as digital signatures or SSL certificate generation. However, it might still be found in legacy systems or used for non-cryptographic purposes like checksums (though stronger alternatives are recommended).

**SHA-1 Collisions:** SHA-1, once a widely used standard, also suffers from collision vulnerabilities, although finding collisions is significantly more computationally expensive than for MD5. In 2017, researchers from Google and CWI Amsterdam announced the first practical SHA-1 collision (dubbed SHAttered), demonstrating it by creating two different PDF files with the same SHA-1 hash. While costly, this proved that SHA-1 is no longer secure for collision-dependent applications. Major browsers and operating systems have since deprecated its use for signatures.

### 3.3 Lab Task: Observing MD5 Collisions

To illustrate how collisions work, we can use pre-computed message blocks that, when appended with common prefixes/suffixes, result in a collision. Several research projects have published such colliding blocks. For this lab, we will use two short, distinct hexadecimal message blocks known to cause an MD5 collision when processed.

Consider these two message blocks (represented in hex):

*   **Block 1:** `d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70`
*   **Block 2:** `d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70`

These blocks are carefully constructed. Let's save them into binary files. We can use Python or a simple command-line tool like `xxd` to convert the hex strings to binary.

**Using Python:**
Create a small Python script `create_colliding_files.py`:

```python
import binascii

hex_block1 = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
hex_block2 = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"

with open("file1.bin", "wb") as f1:
    f1.write(binascii.unhexlify(hex_block1))

with open("file2.bin", "wb") as f2:
    f2.write(binascii.unhexlify(hex_block2))

print("Created file1.bin and file2.bin")
```

Run the script:
```bash
python3 create_colliding_files.py
```

**Verification:**
Now, calculate the MD5 hash of both generated files using the `openssl dgst` command:

```bash
openssl dgst -md5 file1.bin
openssl dgst -md5 file2.bin
```

You should observe that even though `file1.bin` and `file2.bin` contain different data (as confirmed by comparing the hex strings or using a diff tool), they produce the exact same MD5 hash value. This demonstrates a practical MD5 collision.

### 3.4 Length Extension Attacks

Length extension attacks exploit a structural property common to many hash functions based on the Merkle–Damgård construction, including MD5, SHA-1, and SHA-2 (SHA-256, SHA-512). These functions process input messages in fixed-size blocks and maintain an internal state that is updated after processing each block. The final hash output is derived from the final internal state after processing all blocks, including specific padding added to the end of the message.

The attack scenario typically involves a situation where a hash is used as a message authentication code (MAC) in an insecure way, like `hash(secret || message)`, where `secret` is a secret key known only to the server and `||` denotes concatenation. If an attacker knows the `message`, the `hash(secret || message)`, and the `length` of the `secret`, they can often compute `hash(secret || message || padding || arbitrary_extension)` *without knowing the secret itself*. They can effectively append data (`arbitrary_extension`) to the original message and calculate the valid hash for this extended message.

**How it works:** The attacker uses the known hash (`hash(secret || message)`) as the initial internal state. They then calculate the correct padding that would have been applied to `secret || message`. Finally, they process their chosen `arbitrary_extension` starting from that state, producing a valid hash for the longer, forged message (`secret || message || padding || arbitrary_extension`). The crucial point is that the internal state after processing `secret || message` is effectively revealed by its hash value (or can be derived from it), allowing the computation to be resumed.

### 3.5 Lab Task: Performing a Length Extension Attack

We will simulate a scenario where a web application uses `SHA256(secret_key || user_data)` as an authentication token. We, as the attacker, know `user_data`, the resulting hash (token), and the length of `secret_key`, but not the key itself. Our goal is to append malicious data (`&admin=true`) to the `user_data` and generate a valid token for this modified data.

**Scenario Parameters:**
*   Secret Key Length: 14 bytes (we don't know the key, only its length)
*   Original User Data (`user_data`): `user=guest&role=user`
*   Original Token (Hash): `SHA256(secret_key || user_data)` = `c8e31557f57905134ab15990e56d8ab6f60ca1c8d6a4517908d57867f3327519` (This would be observed, e.g., in a cookie or URL)
*   Data to Append (`arbitrary_extension`): `&admin=true`

**3.5.1 Using Python (Conceptual / with Libraries):**
Implementing a length extension attack from scratch in Python requires careful handling of the hash function's padding rules and internal state manipulation. Standard libraries like `hashlib` do not directly expose the internal state needed to resume hashing. However, specialized libraries or custom implementations can demonstrate the principle.

For educational purposes, let's outline the logic:
1.  Determine the padding applied to `secret_key || user_data`. This depends on the combined length (`len(secret_key) + len(user_data)`) and the block size of the hash function (64 bytes for SHA-256). The padding typically involves a '1' bit, followed by '0' bits, and finally the original message length encoded as a 64-bit integer.
2.  Construct the forged message: `user_data || padding || data_to_append`.
3.  Initialize a new SHA-256 computation, but crucially, *set its initial internal state* to the values derived from the original known hash (`c8e3...`).
4.  Feed only the `data_to_append` into this initialized SHA-256 computation.
5.  The resulting hash will be the valid hash for `secret_key || user_data || padding || data_to_append`.

Libraries like `hlextend` (available via pip) can perform this attack. If using `hlextend`:

```python
# Example using hlextend (install with: pip install hlextend)
import hlextend

sha256 = hlextend.new('sha256')

original_data = b"user=guest&role=user"
original_sig = "c8e31557f57905134ab15990e56d8ab6f60ca1c8d6a4517908d57867f3327519"
key_length = 14
data_to_add = b"&admin=true"

# Calculate the extended signature and new message
new_sig, new_message = sha256.extend(data_to_add, original_data, key_length, original_sig, raw=True)

print(f"Original Data: {original_data}")
print(f"Original Sig : {original_sig}")
print(f"Data to Add  : {data_to_add}")
print("---")
# The new_message includes the original data, padding, and added data
print(f"Forged Message: {new_message}") 
print(f"New Sig      : {new_sig.hex()}")

# Verification (requires knowing the secret - for demonstration only)
# import hashlib
# secret_key = b'SECRET_KEY_1234' # Example 14-byte key
# combined_message = secret_key + new_message
# verification_hash = hashlib.sha256(combined_message).hexdigest()
# print(f"Verification : {verification_hash}")
# assert new_sig.hex() == verification_hash
```
Running this script (after installing `hlextend`) will output the forged message (including padding) and the corresponding valid SHA-256 signature.

**3.5.2 Using HashPump:**
HashPump is a command-line tool specifically designed for performing hash length extension attacks.

**Installation (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install hashpump
```
(For other systems or if not in repositories, you may need to build from source: `git clone https://github.com/bwall/HashPump.git && cd HashPump && make && sudo make install`)

**Command Syntax and Execution:**
The basic syntax is:
`hashpump -s <original_signature> -d <original_data> -k <key_length> -a <data_to_add> [--hash <algorithm>]`

Let's apply it to our scenario (SHA-256 is the default hash for HashPump if not specified):

```bash
hashpump -s c8e31557f57905134ab15990e56d8ab6f60ca1c8d6a4517908d57867f3327519 -d "user=guest&role=user" -k 14 -a "&admin=true"
```

**Interpreting the Output:**
HashPump will output two crucial pieces of information:
1.  The new, valid signature (hash) for the extended message.
2.  The exact extended message that produces this signature. This will be the original data, followed by the calculated padding (represented as hex escapes like `\x80\x00...`), followed by the data you wanted to append.

Example Output (structure may vary slightly):
```
c21a95...[new hash value]...
user=guest&role=user\x80\x00\x00...[padding bytes]...\x01\xb0&admin=true
```

The first line is the new signature (`hash(secret || original_data || padding || added_data)`). The second line is the full message (`original_data || padding || added_data`) that needs to be sent to the server along with the new signature to exploit the vulnerability. The server, calculating `hash(secret || received_message)`, will compute the same new signature, thus validating the request, even though it now includes `&admin=true`.

This lab task demonstrates that simply hashing concatenated secrets and data is insufficient for message authentication due to the possibility of length extension attacks. Secure alternatives like HMAC (Hash-based Message Authentication Code), e.g., `HMAC-SHA256`, should always be used for this purpose.
