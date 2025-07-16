import pytest
import pandas as pd
from pathlib import Path
from src.traffic_detect.data.processors.pcap_processor import PcapProcessor

class TestPcapProcessor:
    @pytest.fixture
    def test_file_path(self):
        """返回测试PCAP文件的路径"""
        return Path(__file__).parent.parent.parent / 'data' / 'raw' / 'test.pcapng'

    @pytest.fixture
    def processor(self):
        """返回一个配置好的处理器实例"""
        return PcapProcessor({
            'display_filter': '',
            'max_packets': 1000
        })

    def test_process_file(self, processor, test_file_path):
        """测试处理PCAP文件"""
        if not test_file_path.exists():
            pytest.skip(f"测试文件不存在: {test_file_path}")

        # 处理文件
        df = processor.process(str(test_file_path))
        
        # 验证结果
        assert isinstance(df, pd.DataFrame)
        assert len(df) > 0, "处理结果为空"
        
        # 验证关键字段存在
        required_columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
        for col in required_columns:
            assert col in df.columns, f"缺少字段: {col}"

    def test_packet_structure(self, processor, test_file_path):
        """验证包的基本结构"""
        if not test_file_path.exists():
            pytest.skip(f"测试文件不存在: {test_file_path}")

        df = processor.process(str(test_file_path))
        
        # 验证时间戳格式
        assert 'timestamp' in df.columns
        assert df['timestamp'].dtype == float
        
        # 验证IP地址格式
        assert 'src_ip' in df.columns
        assert 'dst_ip' in df.columns
        assert df['src_ip'].dtype == object
        assert df['dst_ip'].dtype == object

    def test_protocol_detection(self, processor, test_file_path):
        """验证协议检测"""
        if not test_file_path.exists():
            pytest.skip(f"测试文件不存在: {test_file_path}")

        df = processor.process(str(test_file_path))
        
        # 验证协议字段
        assert 'protocol' in df.columns
        assert df['protocol'].dtype == object
        
        # 检查协议值是否合理
        protocols = df['protocol'].unique()
        assert len(protocols) > 0, "没有检测到任何协议"
        assert all(isinstance(p, str) for p in protocols), "协议值不是字符串类型"
