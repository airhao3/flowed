#!/usr/bin/env python3
"""
Script to check the trained model's feature names and compare with expected features.
"""
import joblib
import json
from pathlib import Path

def main():
    # Paths
    model_path = Path("data/models/model.joblib")
    feature_names_path = Path("data/models/feature_names.json")
    
    # Expected features from the prediction code
    expected_features = [
        'flow_pkt_count', 'flow_byte_count', 'flow_duration_seconds',
        'flow_pkts_per_sec', 'flow_bytes_per_sec', 'flow_bytes_per_packet',
        'src_host_pkt_count_win', 'src_host_byte_count_win',
        'src_host_distinct_dst_ips_win', 'src_host_distinct_dst_ports_win',
        'src_host_dst_port_entropy_win', 'dst_host_pkt_count_win',
        'dst_host_byte_count_win', 'dst_host_distinct_src_ips_win',
        'tcp_flag_syn', 'tcp_flag_ack'
    ]
    
    print("=== Model Feature Verification ===")
    
    # Check if model exists
    if not model_path.exists():
        print(f"Error: Model not found at {model_path}")
        return
    
    # Load the model
    try:
        model = joblib.load(model_path)
        print(f"Model loaded successfully from {model_path}")
    except Exception as e:
        print(f"Error loading model: {e}")
        return
    
    # Check if feature names are available in the model
    if hasattr(model, 'feature_names_'):
        model_features = model.feature_names_
        print(f"Model has {len(model_features)} features:")
        for i, feat in enumerate(model_features, 1):
            print(f"  {i}. {feat}")
    else:
        print("Model does not have feature_names_ attribute")
    
    # Check feature names file
    if feature_names_path.exists():
        try:
            with open(feature_names_path, 'r') as f:
                saved_features = json.load(f)
            print(f"\nSaved feature names ({len(saved_features)} features):")
            for i, feat in enumerate(saved_features, 1):
                print(f"  {i}. {feat}")
            
            # Compare with expected features
            print("\nFeature comparison:")
            missing_in_expected = set(saved_features) - set(expected_features)
            missing_in_saved = set(expected_features) - set(saved_features)
            
            if not missing_in_expected and not missing_in_saved:
                print("  ✓ Saved features match expected features")
            else:
                if missing_in_expected:
                    print(f"  ✗ Features in saved but not in expected: {missing_in_expected}")
                if missing_in_saved:
                    print(f"  ✗ Features in expected but not in saved: {missing_in_saved}")
                    
        except Exception as e:
            print(f"Error reading feature names file: {e}")
    else:
        print("\nFeature names file not found")
    
    print("\nVerification complete.")

if __name__ == "__main__":
    main()
