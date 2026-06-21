import pandas as pd
# pyrefly: ignore [missing-import]
import matplotlib.pyplot as plt
import os

file_sizes = ["1MiB", "100MiB"]

def plot_benchmark(name):
    csv_file = f"benchmarks/benchmark_{name}.csv"
    if not os.path.exists(csv_file):
        print(f"{csv_file} not found, skipping...")
        return
        
    df = pd.read_csv(csv_file)
    
    plt.figure(figsize=(10, 5))
    modes = [col for col in df.columns if col != 'Run']
    
    colors = {
        'aes128': 'blue',
        'aes192': 'green',
        'aes256': 'red'
    }
    
    for mode in modes:
        plt.plot(df['Run'], df[mode], label=mode.upper(), color=colors.get(mode, 'black'))
        
    plt.title(f"Thời gian thực thi (Encrypt CTR): benchmark_{name}.csv")
    plt.xlabel("Số lần chạy (Run)")
    plt.ylabel("Thời gian (Giây)")
    plt.grid(True)
    plt.legend()
    
    plot_out = f"benchmarks/plot_{name}.png"
    plt.savefig(plot_out)
    plt.close()
    print(f"Saved plot to {plot_out}")

if __name__ == "__main__":
    for size in file_sizes:
        plot_benchmark(size)
