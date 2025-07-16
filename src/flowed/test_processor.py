from pathlib import Path
from loguru import logger
from .data.processors.pcap_processor import PcapProcessor

def test_processor():
    """测试PCAP处理器的功能"""
    # 初始化处理器
    processor = PcapProcessor({
        'display_filter': '',  # 不使用过滤器，处理所有流量
        'max_packets': 1000   # 最多处理1000个包
    })
    
    # 获取测试文件路径
    test_file = Path(__file__).parent.parent / 'data' / 'raw' / 'test.pcapng'
    
    if not test_file.exists():
        logger.error(f"测试文件不存在: {test_file}")
        return
    
    # 处理PCAP文件
    logger.info(f"开始处理文件: {test_file}")
    df = processor.process(str(test_file))
    
    # 打印基本信息
    logger.info(f"处理结果: {df.shape[0]} 个包")
    logger.info("\n前5行数据:")
    print(df.head())
    
    # 检查关键字段是否存在
    required_columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        logger.error(f"缺少必要字段: {missing_columns}")
    else:
        logger.success("所有必要字段都存在")

if __name__ == '__main__':
    test_processor()
