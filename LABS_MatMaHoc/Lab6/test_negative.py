import os
import subprocess
import sys

def run_cmd(cmd, expect_fail=False):
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 and not expect_fail:
        print(f"Command failed unexpectedly:\n{result.stderr}")
        sys.exit(1)
    if result.returncode == 0 and expect_fail:
        print(f"Command succeeded but was expected to fail!")
        sys.exit(1)
    if expect_fail:
        print(f"Command correctly failed: {result.stderr.strip() or result.stdout.strip()}")
    else:
        print("Command succeeded.\n")

def write_file(path, content):
    with open(path, "wb") as f:
        f.write(content)

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def main():
    if not os.path.exists("./pqtool.exe"):
        print("Please compile pqtool.exe first.")
        sys.exit(1)
        
    print("=== Testing ML-DSA-44 ===")
    
    # 1. Keygen
    run_cmd(["./pqtool.exe", "keygen", "--algo", "mldsa-44", "--pub", "pub.pem", "--priv", "priv.pem"])
    
    # 2. Sign
    msg = b"This is a secret message to sign."
    write_file("msg.bin", msg)
    # The requirement CLI: pqtool sign --algo mldsa-44 --in msg.bin --out sig.bin
    # The tool automatically looks for priv.pem if --priv is missing.
    run_cmd(["./pqtool.exe", "sign", "--algo", "mldsa-44", "--in", "msg.bin", "--out", "sig.bin"])
    
    # 3. Verify (Positive)
    run_cmd(["./pqtool.exe", "verify", "--algo", "mldsa-44", "--in", "msg.bin", "--sig", "sig.bin", "--pub", "pub.pem"])
    
    # 4. Negative Test: Modified Message
    print("\n--- Negative Test: Modified Message ---")
    write_file("msg_mod.bin", b"This is a tampered message to sign.")
    run_cmd(["./pqtool.exe", "verify", "--algo", "mldsa-44", "--in", "msg_mod.bin", "--sig", "sig.bin", "--pub", "pub.pem"], expect_fail=True)
    
    # 5. Negative Test: Modified Signature
    print("\n--- Negative Test: Modified Signature ---")
    sig = bytearray(read_file("sig.bin"))
    sig[10] ^= 0x01 # flip a bit
    write_file("sig_mod.bin", sig)
    run_cmd(["./pqtool.exe", "verify", "--algo", "mldsa-44", "--in", "msg.bin", "--sig", "sig_mod.bin", "--pub", "pub.pem"], expect_fail=True)
    
    # 6. Negative Test: Wrong Public Key
    print("\n--- Negative Test: Wrong Public Key ---")
    run_cmd(["./pqtool.exe", "keygen", "--algo", "mldsa-44", "--pub", "pub_wrong.pem", "--priv", "priv_wrong.pem"])
    run_cmd(["./pqtool.exe", "verify", "--algo", "mldsa-44", "--in", "msg.bin", "--sig", "sig.bin", "--pub", "pub_wrong.pem"], expect_fail=True)
    
    
    print("\n=== Testing ML-KEM-512 ===")
    # 1. Keygen
    run_cmd(["./pqtool.exe", "keygen", "--algo", "mlkem-512", "--pub", "kem_pub.pem", "--priv", "kem_priv.pem"])
    
    # 2. Encaps
    run_cmd(["./pqtool.exe", "encaps", "--algo", "mlkem-512", "--pub", "kem_pub.pem", "--ct", "ct.bin", "--ss", "ss.bin"])
    
    # 3. Decaps (Positive)
    run_cmd(["./pqtool.exe", "decaps", "--algo", "mlkem-512", "--priv", "kem_priv.pem", "--ct", "ct.bin", "--ss", "ss_decaps.bin"])
    ss1 = read_file("ss.bin")
    ss2 = read_file("ss_decaps.bin")
    if ss1 != ss2:
        print("Shared secrets do not match in positive test!")
        sys.exit(1)
        
    # 4. Negative Test: Modified Ciphertext
    print("\n--- Negative Test: Modified Ciphertext ---")
    ct = bytearray(read_file("ct.bin"))
    ct[50] ^= 0x01 # flip a bit
    write_file("ct_mod.bin", ct)
    # ML-KEM uses implicit rejection (FO transform), so it returns a pseudorandom shared secret instead of failing
    run_cmd(["./pqtool.exe", "decaps", "--algo", "mlkem-512", "--priv", "kem_priv.pem", "--ct", "ct_mod.bin", "--ss", "ss_bad.bin"])
    if read_file("ss_bad.bin") == read_file("ss.bin"):
        print("Tampered ciphertext produced the same shared secret! Test failed.")
        sys.exit(1)
    else:
        print("Command correctly generated a different pseudorandom shared secret (Implicit Rejection).")
    
    # 5. Negative Test: Wrong Private Key
    print("\n--- Negative Test: Wrong Private Key ---")
    run_cmd(["./pqtool.exe", "keygen", "--algo", "mlkem-512", "--pub", "kem_pub_wrong.pem", "--priv", "kem_priv_wrong.pem"])
    run_cmd(["./pqtool.exe", "decaps", "--algo", "mlkem-512", "--priv", "kem_priv_wrong.pem", "--ct", "ct.bin", "--ss", "ss_bad_key.bin"])
    if read_file("ss_bad_key.bin") == read_file("ss.bin"):
        print("Wrong private key produced the same shared secret! Test failed.")
        sys.exit(1)
    else:
        print("Command correctly generated a different pseudorandom shared secret (Implicit Rejection).")
    
    print("\nAll tests passed successfully!")

if __name__ == "__main__":
    main()
