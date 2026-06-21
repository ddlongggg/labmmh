import os
import subprocess
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
        plt.plot(df['Run'], df[mode], label=mode.upper(), color=colors.get(mode, 'black'))
        
    plt.title(f"Thời gian thực thi (Encrypt): benchmark_{name}.csv")
    plt.xlabel("Số lần chạy (Run)")
    plt.ylabel("Thời gian (Giây)")
    plt.grid(True)
    plt.legend()
    
    plot_out = f"benchmarks/plot_{name}.png"
    plt.savefig(plot_out)
    plt.close()
    print(f"Saved plot to {plot_out}")

if __name__ == "__main__":
    run_benchmarks()
