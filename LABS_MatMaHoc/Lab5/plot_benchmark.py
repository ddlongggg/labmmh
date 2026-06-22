import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Read the benchmark data
try:
    df = pd.read_csv('build/benchmark_results.csv')
except FileNotFoundError:
    print("Error: benchmark_results.csv not found. Please run the benchmark program first.")
    exit(1)

# Set the style
sns.set_theme(style="whitegrid")

# Create separate charts for Sign and Verify
for operation in ['Sign', 'Verify']:
    df_op = df[df['Operation'] == operation]
    
    # 1. Latency Plot
    plt.figure(figsize=(10, 6))
    ax1 = sns.barplot(x='MessageSize', y='LatencyMs', hue='Algorithm', data=df_op, palette="viridis")
    plt.title(f'{operation} Latency vs Message Size')
    plt.xlabel('Message Size (Bytes)')
    plt.ylabel('Latency (ms)')
    plt.yscale('log') # Log scale because sizes vary a lot
    
    # Format x-axis labels
    labels = []
    for val in ax1.get_xticks():
        size = df_op['MessageSize'].unique()[val]
        if size >= 1024 * 1024:
            labels.append(f'{size / (1024*1024):.0f} MiB')
        else:
            labels.append(f'{size / 1024:.0f} KiB')
    ax1.set_xticklabels(labels)
    
    plt.tight_layout()
    plt.savefig(f'{operation}_Latency.png')
    print(f"Saved {operation}_Latency.png")
    plt.close()

    # 2. Throughput Plot
    plt.figure(figsize=(10, 6))
    ax2 = sns.barplot(x='MessageSize', y='ThroughputOpsSec', hue='Algorithm', data=df_op, palette="mako")
    plt.title(f'{operation} Throughput vs Message Size')
    plt.xlabel('Message Size (Bytes)')
    plt.ylabel('Throughput (Ops/sec)')
    plt.yscale('log')
    
    ax2.set_xticklabels(labels)
    
    plt.tight_layout()
    plt.savefig(f'{operation}_Throughput.png')
    print(f"Saved {operation}_Throughput.png")
    plt.close()

print("All charts generated successfully.")
