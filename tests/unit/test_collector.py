"""Unit tests for the data collector."""
import os
import tempfile
from pathlib import Path

import pytest

# This assumes the project is installed in editable mode or path is adjusted
from src.traffic_detect.data.collector import DataCollector

@pytest.fixture
def temp_dir():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create some test files
        test_files = [
            'test1.pcap',
            'test2.pcap',
            'subdir/test3.pcap',
            'other.txt'
        ]
        
        for file in test_files:
            file_path = Path(temp_dir) / file
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.touch()
        
        yield temp_dir

def test_collect_files(temp_dir):
    """Test that files are collected correctly."""
    config = {
        'input_dir': temp_dir,
        'file_pattern': '*.pcap'
    }
    
    collector = DataCollector(config)
    files = collector.collect()
    
    # Should find 3 PCAP files
    assert len(files) == 3
    assert all(f.endswith('.pcap') for f in files)

def test_empty_directory():
    """Test behavior with empty directory."""
    with tempfile.TemporaryDirectory() as empty_dir:
        config = {
            'input_dir': empty_dir,
            'file_pattern': '*.pcap'
        }
        
        collector = DataCollector(config)
        files = collector.collect()
        
        assert len(files) == 0

def test_nonexistent_directory(caplog):
    """Test behavior with non-existent directory."""
    non_existent_path = '/tmp/nonexistent/path/for/testing'
    if os.path.exists(non_existent_path):
        os.rmdir(non_existent_path) # Ensure it doesn't exist

    config = {
        'input_dir': non_existent_path,
        'file_pattern': '*.pcap'
    }
    
    collector = DataCollector(config)
    files = collector.collect()
    
    # Should create the directory and return empty list
    assert os.path.exists(non_existent_path)
    assert len(files) == 0
    assert f"Input directory {non_existent_path} does not exist" in caplog.text
    os.rmdir(non_existent_path) # Clean up
