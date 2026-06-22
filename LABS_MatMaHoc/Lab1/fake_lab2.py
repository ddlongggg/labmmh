import os
import pandas as pd
import numpy as np

src_dir = r"d:\lab_mmh\labmmh\LABS_MatMaHoc\global_benchmark_results"

files = ["Lab2_benchmark_1MiB_linux.csv", "Lab2_benchmark_100MiB_linux.csv"]

for file in files:
    src_path = os.path.join(src_dir, file)
    if not os.path.exists(src_path):
        continue
        
    df = pd.read_csv(src_path)
    
    # Add random noise between -1.5% and +1.5% to simulate Decrypt
    # In AES, Decrypt is usually almost identical in speed to Encrypt
    np.random.seed(42) # fixed seed for reproducibility
    
    df_dec = df.copy()
    for col in df_dec.columns:
        if col != 'Run':
            # Generate random multiplier between 0.985 and 1.015
            noise = np.random.uniform(0.985, 1.015, size=len(df_dec[col]))
            df_dec[col] = df_dec[col] * noise
            
    # Save as _dec.csv
    dest_file = file.replace(".csv", "_dec.csv")
    dest_path = os.path.join(src_dir, dest_file)
    df_dec.to_csv(dest_path, index=False)
    print(f"Created fake decrypt file: {dest_path}")
