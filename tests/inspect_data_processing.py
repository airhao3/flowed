"""
Script to inspect data processing steps before model training.
This script processes the test data up to the point before model training
and saves the results for inspection.
"""
import os
import sys
import numpy as np
import pandas as pd
from pathlib import Path
import json

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / 'src'))

# Create output directory for inspection
output_dir = Path(__file__).parent / 'inspection_results'
os.makedirs(output_dir, exist_ok=True)

def process_test_data():
    """Process test data and save results for inspection."""
    # Create sample test data (similar to test file)
    np.random.seed(42)
    X = np.random.normal(0, 1, (100, 5))
    X[50:] += 10  # Add some anomalies
    df = pd.DataFrame(X, columns=[f'feat_{i}' for i in range(5)])
    
    # Add some test cases for data processing
    # 1. Add a column with missing values
    df['feat_with_missing'] = np.random.rand(100)
    df.loc[10:20, 'feat_with_missing'] = np.nan
    
    # 2. Add a column with infinite values
    df['feat_with_inf'] = np.random.rand(100)
    df.loc[30:35, 'feat_with_inf'] = np.inf
    df.loc[36:40, 'feat_with_inf'] = -np.inf
    
    # 3. Add a constant column (zero variance)
    df['constant_feat'] = 1.0
    
    # 4. Add a count-like column
    df['count_feat'] = np.random.randint(0, 10, 100)
    
    # Save original data
    df.to_csv(output_dir / '01_original_data.csv', index=False)
    
    # 1. Select only numeric columns
    numeric_features = df.select_dtypes(include=['number']).copy()
    numeric_features.to_csv(output_dir / '02_numeric_features.csv', index=False)
    
    # 2. Handle infinite values
    inf_counts = np.isinf(numeric_features.values).sum()
    if inf_counts > 0:
        print(f"Found {inf_counts} infinite values. Replacing with NaN.")
        numeric_features = numeric_features.replace([np.inf, -np.inf], np.nan)
    numeric_features.to_csv(output_dir / '03_after_inf_handling.csv', index=False)
    
    # 3. Handle missing values
    missing_stats = numeric_features.isnull().sum()
    if missing_stats.sum() > 0:
        missing_cols = missing_stats[missing_stats > 0]
        print(f"Found {missing_stats.sum()} missing values in {len(missing_cols)} columns.")
        
        # Store missing value stats
        missing_stats.to_csv(output_dir / 'missing_values_stats.csv')
        
        # Apply imputation
        for col in missing_cols.index:
            if 'count' in col.lower() or 'flag' in col.lower():
                numeric_features[col].fillna(0, inplace=True)
                print(f"Filled missing values in {col} with 0 (count/flag column)")
            else:
                median_val = numeric_features[col].median()
                numeric_features[col].fillna(median_val, inplace=True)
                print(f"Filled missing values in {col} with median: {median_val:.4f}")
    
    numeric_features.to_csv(output_dir / '04_after_missing_handling.csv', index=False)
    
    # 4. Remove zero-variance columns
    zero_var_cols = []
    for col in numeric_features.columns:
        if numeric_features[col].std() == 0:
            zero_var_cols.append(col)
    
    if zero_var_cols:
        print(f"Removing zero-variance columns: {', '.join(zero_var_cols)}")
        numeric_features.drop(columns=zero_var_cols, inplace=True)
    
    numeric_features.to_csv(output_dir / '05_after_zero_var_removal.csv', index=False)
    
    # Save processing summary
    summary = {
        'original_shape': df.shape,
        'final_shape': numeric_features.shape,
        'columns_removed': list(set(df.columns) - set(numeric_features.columns)),
        'columns_kept': list(numeric_features.columns),
        'missing_values_before': int(missing_stats.sum()),
        'missing_values_after': int(numeric_features.isnull().sum().sum()),
        'infinite_values_found': int(inf_counts)
    }
    
    with open(output_dir / 'processing_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("\n=== Data Processing Summary ===")
    print(f"Original data shape: {summary['original_shape']}")
    print(f"Final data shape: {summary['final_shape']}")
    print(f"Columns removed: {summary['columns_removed']}")
    print(f"Missing values before: {summary['missing_values_before']}")
    print(f"Missing values after: {summary['missing_values_after']}")
    print(f"Infinite values found: {summary['infinite_values_found']}")
    print(f"\nProcessing complete. Results saved to: {output_dir}")

if __name__ == "__main__":
    process_test_data()
