import matplotlib.pyplot as plt
import numpy as np
import os
import csv
from collections import defaultdict

def parse_csv(filepath):
    # Returns a dictionary: {algo: {'Stream': avg_mbps, 'MMap': avg_mbps}}
    data = defaultdict(lambda: {'Stream': [], 'MMap': []})
    if not os.path.exists(filepath):
        print(f"Warning: File {filepath} not found.")
        return None

    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            algo = row['Algorithm']
            data[algo]['Stream'].append(float(row['Stream_MBps']))
            data[algo]['MMap'].append(float(row['MMap_MBps']))

    # Calculate averages
    averages = {}
    for algo, vals in data.items():
        avg_stream = sum(vals['Stream']) / len(vals['Stream']) if vals['Stream'] else 0
        avg_mmap = sum(vals['MMap']) / len(vals['MMap']) if vals['MMap'] else 0
        averages[algo] = {'Stream': avg_stream, 'MMap': avg_mmap}
    
    return averages

def plot_benchmark(data_dict, title, out_filename):
    if not data_dict:
        return
        
    algorithms = list(data_dict.keys())
    stream_vals = [data_dict[a]['Stream'] for a in algorithms]
    mmap_vals = [data_dict[a]['MMap'] for a in algorithms]

    x = np.arange(len(algorithms))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, stream_vals, width, label='Stream I/O', color='#3498db')
    rects2 = ax.bar(x + width/2, mmap_vals, width, label='Memory-Mapped I/O', color='#e74c3c')

    ax.set_ylabel('Throughput (MB/s)')
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(algorithms)
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    for rect in rects1 + rects2:
        height = rect.get_height()
        ax.annotate(f'{height:.1f}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  
                    textcoords="offset points",
                    ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig(out_filename, dpi=300)
    print(f"Saved {out_filename}")
    plt.close()

if __name__ == "__main__":
    # The python script is executed from the 'build' directory by run_tests.ps1
    # Thus the CSV files should be in the current working directory.
    
    data_1mb = parse_csv('hashing_benchmark_1MB.csv')
    if data_1mb:
        plot_benchmark(data_1mb, 'Hashing Performance - 1 MiB File (Avg over 30 runs)', '../performance_plot_1MB.png')

    data_100mb = parse_csv('hashing_benchmark_100MB.csv')
    if data_100mb:
        plot_benchmark(data_100mb, 'Hashing Performance - 100 MiB File (Avg over 30 runs)', '../performance_plot_100MB.png')
