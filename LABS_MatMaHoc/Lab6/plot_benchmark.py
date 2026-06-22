import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Read the benchmark data
try:
    df = pd.read_csv('build/benchmark_results.csv')
except FileNotFoundError:
    print("Error: benchmark_results.csv not found. Please run benchmark.exe first.")
    exit(1)

# Set the style
sns.set_theme(style="whitegrid")

# Create separate charts for Sign, Verify, KeyGen, Encaps, Decaps
for operation in ['Sign', 'Verify']:
    df_op = df[df['Operation'] == operation]
    if df_op.empty:
        continue
    
    # 1. Latency Plot
    plt.figure(figsize=(10, 6))
    ax1 = sns.barplot(x='MessageSize', y='LatencyMs', hue='Algorithm', data=df_op, palette="viridis", capsize=.1)
    plt.title(f'{operation} Latency vs Message Size')
    plt.xlabel('Message Size (Bytes)')
    plt.ylabel('Latency (ms/op)')
    plt.yscale('log')
    
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
    ax2 = sns.barplot(x='MessageSize', y='Throughput', hue='Algorithm', data=df_op, palette="mako", capsize=.1)
    plt.title(f'{operation} Throughput vs Message Size')
    plt.xlabel('Message Size (Bytes)')
    plt.ylabel('Throughput (MB/s)')
    plt.yscale('log')
    
    ax2.set_xticklabels(labels)
    
    plt.tight_layout()
    plt.savefig(f'{operation}_Throughput.png')
    print(f"Saved {operation}_Throughput.png")
    plt.close()

# Plot KeyGen, Encaps, Decaps Latency together
df_other = df[df['Operation'].isin(['KeyGen', 'Encaps', 'Decaps'])]
if not df_other.empty:
    plt.figure(figsize=(10, 6))
    sns.barplot(x='Operation', y='LatencyMs', hue='Algorithm', data=df_other, palette="magma", capsize=.1)
    plt.title('Other Operations Latency (ms/op)')
    plt.xlabel('Operation')
    plt.ylabel('Latency (ms/op)')
    plt.tight_layout()
    plt.savefig('OtherOps_Latency.png')
    print("Saved OtherOps_Latency.png")
    plt.close()

print("All charts generated successfully with 95% Confidence Intervals.")
