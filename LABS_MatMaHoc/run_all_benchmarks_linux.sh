#!/bin/bash
set -e # Exit on any error

# Go to script directory
cd "$(dirname "$0")"
ROOT_DIR=$(pwd)
mkdir -p "global_benchmark_results"

echo "==========================================="
echo "   STARTING ALL LAB BENCHMARKS (LINUX)"
echo "==========================================="

# ---------------------------------------------------------
# Lab 1
# ---------------------------------------------------------
echo "[+] Running Lab 1 Benchmarks..."
cd "$ROOT_DIR/Lab1"
mkdir -p build_linux && cd build_linux
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..
mkdir -p benchmarks

declare -A sizes1=( ["1KiB"]=1024 ["4KiB"]=4096 ["16KiB"]=16384 ["256KiB"]=262144 ["1MiB"]=1048576 ["8MiB"]=8388608 )
for name in "${!sizes1[@]}"; do
    bytes=${sizes1[$name]}
    payload="benchmarks/payload_${name}.bin"
    csvout="benchmarks/benchmark_${name}_linux.csv"
    if [ ! -f "$payload" ]; then
        echo "    Generating $payload ($bytes bytes)..."
        # Use a larger block size for faster dd if possible
        if [ $bytes -ge 1048576 ]; then
            dd if=/dev/urandom of="$payload" bs=1M count=$((bytes/1048576)) status=none
        else
            dd if=/dev/urandom of="$payload" bs=1 count="$bytes" status=none
        fi
    fi
    echo "    Benchmarking $name..."
    ./build_linux/aestool bench --in "$payload" --out "$csvout" --runs 30
    base="${csvout%.csv}"
    cp "${base}_enc.csv" "$ROOT_DIR/global_benchmark_results/Lab1_benchmark_${name}_linux_enc.csv" 2>/dev/null || true
    cp "${base}_dec.csv" "$ROOT_DIR/global_benchmark_results/Lab1_benchmark_${name}_linux_dec.csv" 2>/dev/null || true
done

# ---------------------------------------------------------
# Lab 2
# ---------------------------------------------------------
echo "[+] Running Lab 2 Benchmarks..."
cd "$ROOT_DIR/Lab2"
mkdir -p build_linux && cd build_linux
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..
mkdir -p benchmarks

declare -A sizes2=( ["1MiB"]=1048576 ["100MiB"]=104857600 )
for name in "${!sizes2[@]}"; do
    bytes=${sizes2[$name]}
    payload="benchmarks/payload_${name}.bin"
    csvout="benchmarks/benchmark_${name}_linux.csv"
    if [ ! -f "$payload" ]; then
        echo "    Generating $payload ($bytes bytes)..."
        if [ $bytes -ge 1048576 ]; then
            dd if=/dev/urandom of="$payload" bs=1M count=$((bytes/1048576)) status=none
        else
            dd if=/dev/urandom of="$payload" bs=1 count="$bytes" status=none
        fi
    fi
    echo "    Benchmarking $name..."
    ./build_linux/aestool2 bench --in "$payload" --out "$csvout" --runs 30
    cp "$csvout" "$ROOT_DIR/global_benchmark_results/Lab2_benchmark_${name}_linux.csv" 2>/dev/null || true
done

# ---------------------------------------------------------
# Lab 3
# ---------------------------------------------------------
echo "[+] Running Lab 3 Benchmarks..."
cd "$ROOT_DIR/Lab3"
mkdir -p build_linux && cd build_linux
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..
./build_linux/rsatool benchmark
for f in *benchmark.csv; do
    if [ -f "$f" ]; then
        cp "$f" "$ROOT_DIR/global_benchmark_results/${f%.csv}_linux.csv"
    fi
done

# ---------------------------------------------------------
# Lab 4
# ---------------------------------------------------------
echo "[+] Running Lab 4 Benchmarks..."
cd "$ROOT_DIR/Lab4"
mkdir -p build_linux && cd build_linux
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..
./build_linux/Lab4_Task5_Benchmark
for f in hashing_benchmark_*.csv; do
    if [ -f "$f" ]; then
        cp "$f" "$ROOT_DIR/global_benchmark_results/${f%.csv}_linux.csv"
    fi
done

# ---------------------------------------------------------
# Lab 5
# ---------------------------------------------------------
echo "[+] Running Lab 5 Benchmarks..."
cd "$ROOT_DIR/Lab5"
mkdir -p build_linux && cd build_linux
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
cd ..
./build_linux/benchmark
if [ -f "benchmark_results.csv" ]; then
    cp "benchmark_results.csv" "$ROOT_DIR/global_benchmark_results/Lab5_benchmark_results_linux.csv"
fi

echo "==========================================="
echo "   ALL BENCHMARKS COMPLETED SUCCESSFULLY!"
echo "   Results are saved in: $ROOT_DIR/global_benchmark_results"
echo "==========================================="
