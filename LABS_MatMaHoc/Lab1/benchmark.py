import os
import subprocess
import glob
import pandas as pd
# pyrefly: ignore [missing-import]
import matplotlib.pyplot as plt

# File sizes to test
file_sizes = {
    "1KiB": 1024,
    "4KiB": 4 * 1024,
    "16KiB": 16 * 1024,
    "256KiB": 256 * 1024,
    "1MiB": 1024 * 1024,
    "8MiB": 8 * 1024 * 1024
}

AESTOOL_PATH = r"build\Debug\aestool.exe"
RUNS = 30

def generate_file(filename, size):
    with open(filename, 'wb') as f:
        f.write(os.urandom(size))

def run_benchmarks():
    os.makedirs("benchmarks", exist_ok=True)
    
    for name, size in file_sizes.items():
        filename = f"benchmarks/payload_{name}.bin"
        csv_out = f"benchmarks/benchmark_{name}.csv"
        
        print(f"Generating {filename} ({size} bytes)...")
        generate_file(filename, size)
        
        print(f"Running benchmarks for {name}...")
        cmd = [AESTOOL_PATH, "bench", "--in", filename, "--out", csv_out, "--runs", str(RUNS)]
        subprocess.run(cmd, check=True)
        
        print(f"Finished {name}. Plotting...")
        plot_benchmark(csv_out, name)

def plot_benchmark(csv_file, name):
    df = pd.read_csv(csv_file)
    
    # Kiểm tra xem có cột 'Run' không (chỉ vẽ cho AES Lab1)
    if 'Run' not in df.columns:
        print(f"Bỏ qua {csv_file} vì không đúng định dạng Lab1.")
        return

    plt.figure(figsize=(10, 5))
    modes = [col for col in df.columns if col != 'Run']
    
    colors = {
        'ecb': 'blue',
        'cbc': 'green',
        'cfb': 'red',
        'ofb': 'orange',
        'ctr': 'purple',
        'gcm': 'pink',
        'ccm': 'cyan',
        'xts': 'brown'
    }
    
    for mode in modes:
        plt.plot(df['Run'], df[mode], label=mode.upper(), color=colors.get(mode.lower(), 'black'))
        
    op_type = "Decrypt" if "dec" in name.lower() else "Encrypt"
    basename = os.path.basename(csv_file)
    
    plt.title(f"Thời gian thực thi ({op_type}): {basename}")
    plt.xlabel("Số lần chạy (Run)")
    plt.ylabel("Thời gian (Giây)")
    plt.grid(True)
    plt.legend()
    
    plot_out = f"benchmarks/plot_{name}.png"
    plt.savefig(plot_out)
    plt.close()
    print(f"Saved plot to {plot_out}")

def plot_global_benchmarks():
    os.makedirs("benchmarks", exist_ok=True)
    global_dir = r"..\global_benchmark_results"
    
    csv_files = glob.glob(os.path.join(global_dir, "Lab1_benchmark_*.csv"))
    
    if not csv_files:
        print(f"Không tìm thấy file CSV nào trong {global_dir}")
        return
        
    for csv_file in csv_files:
        basename = os.path.basename(csv_file)
        name = basename.replace(".csv", "")
        print(f"Plotting {basename}...")
        plot_benchmark(csv_file, name)

if __name__ == "__main__":
    # Đã chuyển sang vẽ từ thư mục global_benchmark_results
    plot_global_benchmarks()
