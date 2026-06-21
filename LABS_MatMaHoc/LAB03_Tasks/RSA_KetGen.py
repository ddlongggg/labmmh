import ctypes
from ctypes import c_uint, c_char_p, c_bool
import argparse
import sys, os

# Add the folder containing dependencies (adjust as necessary)
os.add_dll_directory("D:/msys64/mingw64/bin")

# Load the shared library
rsa_lib = ctypes.CDLL('./GenKey.so', mode=3)  # Use full or relative path

# Define function signature
rsa_lib.RSA_GenKey.argtypes = [c_uint, c_char_p, c_char_p, c_bool, c_bool]
rsa_lib.RSA_GenKey.restype = None

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Generate RSA Keys via .so library")

parser.add_argument("key_length", type=int, help="Length of the RSA key (e.g., 2048)")
parser.add_argument("private_key_base", type=str, help="Base name for private key")
parser.add_argument("public_key_base", type=str, help="Base name for public key")
parser.add_argument("--der", action="store_true", help="Output in DER format")
parser.add_argument("--pem", action="store_true", help="Output in PEM format")

args = parser.parse_args()

# Call the function
rsa_lib.RSA_GenKey(
    c_uint(args.key_length),
    c_char_p(args.private_key_base.encode()),
    c_char_p(args.public_key_base.encode()),
    c_bool(args.der),
    c_bool(args.pem)
)
