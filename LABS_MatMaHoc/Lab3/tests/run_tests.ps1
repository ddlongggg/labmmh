$ErrorActionPreference = "Stop"

# Create build directory and compile
cd ../
mkdir -Force build | Out-Null
cd build
cmake ..
cmake --build . --config Debug

$EXE = "./Debug/rsatool.exe"

# 1. Create Test Files
Write-Host "Creating test files..."
"Short message for RSA" | Out-File -Encoding utf8 "short.bin"
"L" * 10000 | Out-File -Encoding utf8 "long.bin" # Will definitely trigger hybrid encryption

# 2. Key Generation
Write-Host "`n=== Test: Keygen ==="
& $EXE keygen --bits 3072 --pub pub.pem --priv priv.pem

# 3. Direct Encryption & Decryption
Write-Host "`n=== Test: Direct Encryption & Decryption ==="
& $EXE encrypt --in short.bin --pub pub.pem --out short_enc.bin
& $EXE decrypt --in short_enc.bin --priv priv.pem --out short_dec.bin
$orig = Get-Content "short.bin" -Raw
$dec  = Get-Content "short_dec.bin" -Raw
if ($orig -ne $dec) { throw "Direct Decryption Mismatch!" }

# 4. Hybrid Encryption & Decryption
Write-Host "`n=== Test: Hybrid Encryption & Decryption ==="
& $EXE encrypt --in long.bin --pub pub.pem --out long_enc.bin
& $EXE decrypt --in long_enc.bin --priv priv.pem --out long_dec.bin
$orig2 = Get-Content "long.bin" -Raw
$dec2  = Get-Content "long_dec.bin" -Raw
if ($orig2 -ne $dec2) { throw "Hybrid Decryption Mismatch!" }

# 5. Negative Test: Alter RSA Ciphertext
Write-Host "`n=== Negative Test: Alter RSA Ciphertext ==="
$bytes = [IO.File]::ReadAllBytes("$PWD\short_enc.bin")
$bytes[10] = $bytes[10] -bxor 0xFF
[IO.File]::WriteAllBytes("$PWD\short_enc_tampered.bin", $bytes)
& $EXE decrypt --in short_enc_tampered.bin --priv priv.pem --out dummy.bin
if ($LASTEXITCODE -eq 0) { throw "Should have failed!" }
Write-Host "Successfully caught tampered RSA ciphertext" -ForegroundColor Green

# 6. Negative Test: Alter AES Ciphertext
Write-Host "`n=== Negative Test: Alter AES Ciphertext ==="
$bytes2 = [IO.File]::ReadAllBytes("$PWD\long_enc.bin")
$bytes2[100] = $bytes2[100] -bxor 0xFF
[IO.File]::WriteAllBytes("$PWD\long_enc_tampered.bin", $bytes2)
Copy-Item "long_enc.bin.json" "long_enc_tampered.bin.json" # Provide the envelope for it
& $EXE decrypt --in long_enc_tampered.bin --priv priv.pem --out dummy.bin
if ($LASTEXITCODE -eq 0) { throw "Should have failed!" }
Write-Host "Successfully caught tampered AES ciphertext (Tag Verification Failed)" -ForegroundColor Green

# 7. Benchmarks
Write-Host "`n=== Running Benchmarks ==="
& $EXE benchmark

Write-Host "`nAll tests passed successfully!" -ForegroundColor Green
