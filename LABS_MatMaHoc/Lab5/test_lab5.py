import subprocess
import os

# Ensure we are in the Lab5/build or executable directory
# Assuming sigtool is in the current directory or build/
SIGTOOL = "./sigtool.exe" if os.name == 'nt' else "./sigtool"

if not os.path.exists(SIGTOOL):
    SIGTOOL = "./build/sigtool.exe" if os.name == 'nt' else "./build/sigtool"
    if not os.path.exists(SIGTOOL):
        print("sigtool executable not found. Please build the project first.")
        exit(1)

def run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

print("=== Setting up test environment ===")
run_cmd(f"{SIGTOOL} keygen --algo ecdsa-p256 --pub pub.pem --priv priv.pem")
run_cmd(f"{SIGTOOL} keygen --algo ecdsa-p256 --pub pub2.pem --priv priv2.pem")

with open("msg.bin", "wb") as f:
    f.write(b"This is a secret message")

run_cmd(f"{SIGTOOL} sign --algo ecdsa-p256 --in msg.bin --out sig.bin --hash sha256 --priv priv.pem --encode raw")

print("--- Positive Test ---")
code, out, err = run_cmd(f"{SIGTOOL} verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub.pem --hash sha256")
assert code == 0, "Positive test failed!"
print("PASS: Valid signature verified correctly.")

print("\n--- 1. Modified Message Test ---")
with open("msg_bad.bin", "wb") as f:
    f.write(b"This is a public message")
code, out, err = run_cmd(f"{SIGTOOL} verify --algo ecdsa-p256 --in msg_bad.bin --sig sig.bin --pub pub.pem --hash sha256")
assert code != 0, "Modified Message test failed to reject!"
print("PASS: Modified message was correctly rejected.")

print("\n--- 2. Modified Signature Test ---")
with open("sig.bin", "rb") as f:
    sig_data = bytearray(f.read())
sig_data[0] ^= 0xFF # Flip a byte
with open("sig_bad.bin", "wb") as f:
    f.write(sig_data)
code, out, err = run_cmd(f"{SIGTOOL} verify --algo ecdsa-p256 --in msg.bin --sig sig_bad.bin --pub pub.pem --hash sha256")
assert code != 0, "Modified Signature test failed to reject!"
print("PASS: Modified signature was correctly rejected.")

print("\n--- 3. Wrong Public Key Test ---")
code, out, err = run_cmd(f"{SIGTOOL} verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub2.pem --hash sha256")
assert code != 0, "Wrong Public Key test failed to reject!"
print("PASS: Wrong public key correctly rejected the signature.")

print("\n--- 4. Wrong Algorithm / Hash Mismatch Test ---")
code, out, err = run_cmd(f"{SIGTOOL} verify --algo ecdsa-p256 --in msg.bin --sig sig.bin --pub pub.pem --hash sha384")
assert code != 0, "Wrong hash algorithm test failed to reject!"
print("PASS: Wrong hash algorithm was correctly rejected.")

print("\n--- 5. Batch Verification Test ---")
with open("batch.txt", "w") as f:
    f.write("msg.bin sig.bin\n")
    f.write("msg_bad.bin sig.bin\n")
    f.write("msg.bin sig_bad.bin\n")

code, out, err = run_cmd(f"{SIGTOOL} verify --batch batch.txt --algo ecdsa-p256 --pub pub.pem --hash sha256")
# Expect failure because 2 out of 3 are bad
assert code != 0, "Batch verification with bad sigs should fail!"
print("PASS: Batch verification behaved correctly.")

print("\nAll automated tests passed successfully!")

# Cleanup
for f in ["pub.pem", "priv.pem", "pub2.pem", "priv2.pem", "msg.bin", "msg_bad.bin", "sig.bin", "sig_bad.bin", "batch.txt"]:
    if os.path.exists(f):
        os.remove(f)
