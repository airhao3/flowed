# Flowed - 流量异常检测系统 - 设计与架构

## 1. 环境设置

### 1.1. 虚拟环境管理

本项目支持使用 `uv` 或标准 `venv` 作为虚拟环境管理工具。推荐使用 `uv` 以获得更快的依赖安装速度。

#### 使用 uv（推荐）
1. 安装 uv（如果尚未安装）：
```bash
curl -sSf https://astral.sh/uv/install.sh | sh
```

2. 创建并激活虚拟环境：
```bash
uv venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate    # Windows
```

3. 安装项目依赖：
```bash
uv pip install -e .
uv pip install -r requirements.txt
```

#### 使用标准 venv
1. 创建虚拟环境：
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate    # Windows
```

2. 安装项目依赖：
```bash
pip install -e .
pip install -r requirements.txt
```

## 2. 项目愿景与目标

本文档概述了重构后的流量异常检测系统的设计、架构和开发路线图。该项目的主要目标是创建一个健壮、模块化和可扩展的平台，用于分析网络流量数据（PCAP 文件）以识别异常。

重构工作的关键目标是：

- **模块化**：将单体应用程序分解为一组具有明确职责的独立、可重用的模块（例如，数据收集、特征提取、建模）。
- **可维护性**：建立一个清晰、有组织的代码库，易于理解、调试和增强。
- **可扩展性**：设计系统使其易于扩展新功能、模型和数据源，而无需进行重大的架构更改。
- **效率**：实现高效的数据处理，例如将 IP 地址转换为整数以加快处理速度并减少存储空间。
- **可复现性**：通过集中配置和版本化模型，确保分析流程是可配置和可重复的。

## 3. 系统架构

该系统基于标准的机器学习流水线架构设计，每个阶段都封装在自己的模块中。`main.py` 作为中央协调器，协调模块之间的数据流，而 `cli.py` 提供用户友好的命令行界面。

### 3.1 顶层架构概览
[系统整体架构图]
系统由四大核心层构成，形成一个从原始数据到智能决策的单向流水线：
数据采集与标准化层
特征工程与画像层
双引擎AI检测层
告警与可视化层

### 3.2 数据源

系统支持多种数据源，包括：
- **PCAP 文件**：传统的网络数据包捕获文件
- **Arkime 数据**：从 Arkime 网络流量分析平台导出的数据，支持以下功能：
  - 直接连接 Arkime API 获取实时或历史流量数据
  - 支持 Arkime 的 SPI（Session Protocol Index）数据格式
  - 自动解析 Arkime 的会话元数据和协议字段
  - 独立的数据收集和处理流程，与PCAP处理解耦

### 3.3 目录结构

该项目遵循标准的 Python 源代码布局，以便更好地打包和分发：

```
flowed/
├── config/                 # 配置文件目录
│   └── default.yaml        # 默认配置文件
├── data/                   # 工作数据根目录
│   ├── raw/                # 输入: 原始数据文件
│   │   └── pcap/           # PCAP/PCAPNG 文件
│   ├── processed/          # 输出: 处理后的中间数据 (Parquet 格式)
│   │   └── features.parquet # 处理后的特征数据
│   ├── models/             # 输出: 训练好的模型文件
│   │   └── isolation_forest_model/  # 隔离森林模型
│   └── reports/            # 输出: 最终生成的分析报告 (HTML)
├── docs/                    # (未来) 项目文档
├── scripts/                 # 辅助脚本（安装、运行测试）
│   ├── install.sh
│   └── run_tests.sh
├── src/
│   └── flowed/              # 主要源代码包
│       ├── __init__.py
│       ├── cli.py             # 命令行接口
│       ├── main.py            # 主协调器
│       ├── data/              # 数据收集与处理
│       │   ├── sequence_builder.py # 新增：序列构建器
│       │   └── processors/    # 数据处理器
│       │       ├── base_processor.py
│       │       └── pcap_processor.py
│       ├── features/          # 特征工程
│       │   ├── extractor.py   # 特征提取主类
│       │   └── calculators/   # 特征计算器 (分层)
│       │       ├── base_calculator.py
│       │       ├── packet_calculator.py  # L1: 解码TCP标志等
│       │       ├── flow_calculator.py    # L2: 计算单向流统计
│       │       ├── session_calculator.py # L2: 聚合双向流为会话
│       │       ├── host_calculator.py    # L3: 计算主机时间窗口行为
│       │       ├── profile_comparison_calculator.py # L3: 计算与历史画像的对比特征
│       │       └── protocol_calculators/ # L2: 应用层协议解析
│       ├── models/            # 异常检测模型
│       │   ├── __init__.py
│       │   ├── base_model.py  # 模型基类
│       │   ├── isolation_forest.py  # 隔离森林实现
│       │   ├── lstm_autoencoder.py # 新增：LSTM模型实现
│       │   └── model_manager.py     # 模型管理
│       ├── profiles/            # 新增：个体画像管理模块
│       │   ├── profile_store.py   # 新增：画像存储与访问
│       │   └── profile_updater.py # 新增：画像异步更新器
│       ├── utils/             # 工具函数
│       │   ├── config.py      # 配置管理
│       │   └── logger.py      # 日志配置
│       └── visualization/     # 报告与可视化
│           └── dashboard.py   # 报告生成器
├── tests/                   # 自动化测试
│   ├── integration/
│   └── unit/
│       └── test_collector.py
├── .gitignore
├── DESIGN_AND_ARCHITECTURE.md
├── README.md
├── requirements.txt
└── setup.py
```
### 3.4 高层数据处理流程
收集 (Collect)：DataCollector 识别原始数据文件。
摄取与标准化 (Ingest & Standardize)：DataIngestor 选择合适的 Processor 将原始数据转换为标准格式的DataFrame (L1特征)。
富化与特征提取 (Enrich & Extract)：FeatureExtractor 协调所有 Calculator，逐层计算 L2 和 L3 特征，并与 ProfileStore 交互。
检测 (Detect)：ModelManager 使用双引擎模型对特征数据进行评分。
可视化 (Visualize)：ResultVisualizer 生成分析报告。

### 3.5. 双引擎协作模式：分层过滤安检 (Layered Filtering Security Check)

进入系统的每一笔流量（会话），都必须通过两道安检。第一道安检快速、高效，负责处理绝大部分流量；第二道安检则对少数“可疑”流量进行更深入、更细致的盘查。

#### 第一道安检：快速安检通道 (The Fast Lane Security Check)

- **安检员**: “巡警” - **孤立森林 (Isolation Forest)**
- **检查工具**: X光机。它能快速扫描旅客的行李（会话的静态特征向量），发现明显违禁品。

**工作流程**:

1.  **输入**: 一个刚刚结束的会话，已经被`FeatureExtractor`处理成了一个包含L2+L3所有特征的、扁平化的特征向量。
2.  **检查**: 孤立森林模型对这个向量进行快速评分。它寻找的是那些**“一眼看上去就不对劲”**的特征。
3.  **判断与分流**:
    - **红色警报 (High Alert)**: 如果分数远超高风险阈值（例如，得分 > 0.7）。
        - **原因**: 这相当于X光机直接扫出了行李里有一把“大砍刀”——特征值极其异常，比如`src_host_distinct_dst_ports_win = 10000`（端口扫描）或`packets_per_second = 50000`（DDoS）。
        - **动作**: 立即告警，无需复查！ `ModelManager`直接将这个高风险事件发送到告警层，安检流程结束。
    - **绿色通行 (Passed)**: 如果分数很低，完全正常。
        - **原因**: 行李里什么都没有，特征向量完全符合“正常”模式。
        - **动作**: 旅客正常通过。`ModelManager`将这个会话标记为正常，但会静默地将它的特征向量发送给`SequenceBuilder`，用于更新该旅客（IP）的历史行为档案。
    - **黄色标记 (Suspicious)**: 如果分数处于一个“可疑”的灰色地带（例如，0.5 < 得分 <= 0.7）。
        - **原因**: X光机扫出了一个“形状可疑的金属物体”，但无法确定是不是违禁品。特征向量有一些不太常见的组合，但又没有极端到可以直接判定为攻击。
        - **动作**: 引导至第二道安检进行人工复查！ `ModelManager`将这个事件和它的特征向量，传递给下一阶段。

#### 第二道安检：人工详细检查室 (The Detailed Manual Inspection Room)

- **安检员**: “侦探” - **LSTM自编码器 (LSTM Autoencoder)**
- **检查工具**: 开箱检查 + 行为问询。侦探不仅要看这个旅客当前的行李，更重要的是，他会调取该旅客最近一段时间内所有的安检记录（行为序列），并询问他：“你从哪里来？要去哪里？为什么你的行程路线这么奇怪？”

**工作流程**:

1.  **输入**:
    - 来自第一道安检的“黄色标记”事件。
    - `ModelManager`调用`SequenceBuilder`，获取该旅客（客户端IP）最新的、包含了当前这次可疑行为的、完整的行为序列（例如，最近20次会话的特征向量序列）。
2.  **检查**: LSTM自编码器“阅读”这整个行为序列。它利用自己学到的海量“正常旅客行程模式”，来判断这个旅客的**“行程剧本”**是否合乎逻辑。
3.  **判断与最终决策**:
    - **红色警报 (Critical Alert)**: 如果LSTM的重构误差非常高，远超其自身的异常阈值。
        - **原因**: 侦探发现这个旅客的“故事”讲不通。例如，“他说他只是来旅游，但他先去了电厂，又去了水坝，最后出现在银行金库门口，这不符合任何正常游客的逻辑！”（业务逻辑滥用）；或者，“他每隔5分钟就以完全相同的姿势敬个礼，持续了24小时”（C2心跳）。
        - **动作**: 确认威胁，立即告警！ `ModelManager`生成一个更高级别的“序列异常”告警，并附上LSTM的分析结果。
    - **绿色放行 (Cleared)**: 如果LSTM的重构误差很低。
        - **原因**: 侦探发现虽然他这次行李里有个奇怪的金属物体，但他之前的行程都非常正常，并且这次也能给出合理解释。这个行为序列的“语法”是通顺的。
        - **动作**: 解除嫌疑，正常放行。 `ModelManager`最终将该事件判定为正常。

#### 协作流程总结

这个双引擎协作流程，可以用以下伪代码在`ModelManager`中清晰地表达出来：

```python
function collaborative_predict(feature_vector):
    # 第一层：快速筛选
    iso_forest_score = isolation_forest.predict_score(feature_vector)
    
    # 对于所有通过初筛的流量，都更新其行为序列
    client_ip = feature_vector['client_ip']
    sequence_builder.update_sequence(client_ip, feature_vector)

    # 第二层：仅对可疑流量进行深度分析
    if iso_forest_score > SUSPICIOUS_THRESHOLD:
        
        # 获取完整的行为序列
        sequence = sequence_builder.get_sequence(client_ip)
        
        if sequence is long_enough:
            lstm_score = lstm_autoencoder.predict_score(sequence)
            
            if lstm_score > LSTM_ANOMALY_THRESHOLD:
                return create_alert("Critical", "LSTM", "Behavioral sequence anomaly")

    # 如果所有检查都通过
    return mark_as_normal(iso_forest_score)
```

#### 核心优势

- **高效**: 绝大部分流量都被快速的孤立森林处理了，避免了对所有流量都进行昂贵的LSTM分析。
- **精准**: 对于那些孤立森林难以判断的、更狡猾的攻击，我们有专门的“侦探”LSTM来进行深度调查，从而降低误报，并发现隐藏的威胁。
- **互补**: 孤立森林擅长发现**“静态”和“突变”的异常，而LSTM擅长发现“动态”和“时序”**的异常，两者能力完美互补，覆盖了更广的攻击面。


## 4. 模块详解 

### 4.1. 数据采集与标准化

*本章节整合所有与“获取原始数据并将其标准化”相关的内容。*
#### 4.1.1 核心组件

 - DataIngestor: 数据摄取的统一入口，动态选择解析器。
 - PcapProcessor: 使用 pyshark 将PCAP文件解析为包含L1协议字段的DataFrame。
#### 4.1.2. 协议解析能力 (L1 特征提取)
 PcapProcessor 负责将原始数据包转化为结构化信息，提取以下关键协议字段：
 - TCP: tcp.flags, tcp.srcport, tcp.dstport, tcp.seq, tcp.ack 等。
 - HTTP: http.request.method, http.request.uri, http.user_agent, http.host, http.response.code 等。
 - DNS: dns.qry.name, dns.qry.type, dns.flags.rcode 等。
 - TLS/SSL: 从Client Hello消息中提取字段，用于计算 JA3 指纹。
 - 其他: SSH版本信息, TDS (SQL) 查询语句等。

### 4.2. 特征工程：从数据到洞察

这是系统的核心技术章节，整合所有与“将标准化数据转化为模型输入”相关的内容。

### 4.2.1 核心概念定义

 - 流 (Flow): 指网络中具有相同五元组（源IP、源端口、目的IP、目的端口、协议）的单向数据包序列。
 - 会话 (Session): 指两个端点之间的一个完整的、双向的逻辑通信。它由一个或多个相关的流组成。
 - 主机 (Host): 指网络中的一个设备，通过其IP地址进行标识。

 ### 4.2.2. FeatureExtractor: 特征提取协调器


1. FeatureExtractor 是特征工程模块的核心，它不亲自执行计算，而是像一个总指挥，按逻辑顺序调用一系列专门的“特征计算器” (Calculator)，实现从原始数据到高级上下文特征的逐层聚合。
2. 特征提取黄金流程 (Golden Pipeline):
3. 调用 PacketCalculator (L1): 解码TCP标志位等基础意图。
4. 调用 FlowCalculator (L2): 聚合数据包为单向流，计算流级统计特征。
5. 调用 ProtocolCalculators (L2): 对特定协议载荷进行深度解析，提取应用层特征。
6. 调用 SessionCalculator (L2): 聚合相关流为双向会话，计算会话级整体统计特征。
7. 调用 HostCalculator (L3): 在时间窗口内聚合会话，计算主机的宏观行为特征。
8. 调用 ProfileComparisonCalculator (L3): 从 ProfileStore 获取历史画像，对比当前行为，生成最终的“偏差”特征。

## 4.3 模块详解

### 4.3.1. `main.py`: 协调器
- **职责**：包含 `TrafficDetector` 类，该类初始化所有组件并执行端到端的分析流水线。
- **设计**：它不处理任何命令行解析。它由 `cli.py` 实例化和驱动。其主要方法 `run()` 按顺序调用收集器、处理器、提取器、检测器和可视化器。

### 4.3.2. `cli.py`: 命令行界面
- **职责**：为从命令行运行应用程序提供用户友好的入口点。
- **设计**：它使用 `argparse` 来处理命令行参数（例如 `--train`）。它实例化并运行 `main.py` 中的 `TrafficDetector`。

### 4.3.3. `utils/config.py`: 配置管理
- **职责**：加载、合并和提供对 YAML 配置文件中配置设置的访问。
- **设计**：`Config` 类加载默认配置，并可以使用用户提供的文件覆盖它。这使得可以轻松管理文件路径、模型设置和功能标志等参数。

### 4.3.4. `data/collector.py`: 数据收集
- **职责**：查找并收集用于处理的原始数据文件（PCAP）。
- **设计**：`DataCollector` 类扫描指定目录（`data/raw/`）以查找 PCAP 文件，并返回其路径列表。

### 4.3.5.  `data/`: 统一数据摄取层
为了支持多种数据源并标准化处理流程，数据处理模块被重构为一个统一的数据摄取层。

- **`data/ingestor.py`**: `DataIngestor` 是数据摄取的入口。它会根据文件类型或配置，动态选择合适的解析器（Processor）来处理原始数据。

- **`data/arkime_collector.py`**: 负责从 Arkime 平台收集和处理网络流量数据。主要功能包括：
  - 连接到 Arkime API 并执行查询
  - 将 Arkime 会话数据转换为标准格式
  - 处理分页和大型结果集
  - 支持时间范围过滤和字段选择

- **`data/processors/base_processor.py`**: 定义了一个抽象基类 `BaseProcessor`，它规定了所有具体解析器必须实现一个统一的 `process` 接口。该接口的返回值是一个标准化的 pandas DataFrame。

- **`data/processors/pcap_processor.py`**: 一个具体的解析器实现，负责处理 PCAP 文件。它使用 `pyshark` 提取网络包信息，并将其转换为标准格式的 DataFrame。经过增强，它现在可以解析并提取包括 **HTTP、SSH、TDS (SQL)** 在内的多种应用层协议的关键字段。

- **未来扩展**: 要支持新的数据源（如 NetFlow），只需在 `processors` 目录下创建一个新的解析器文件（如 `netflow_processor.py`），实现 `BaseProcessor` 接口即可。`DataIngestor` 可以自动发现并使用它。

### 4.4 特征工程

#### 4.4.1 新增特征字段

##### 4.4.1.1 基础网络特征
- `flow_key`: 流的唯一标识符，格式为 `src_ip:src_port-dst_ip:dst_port`
- `direction`: 流量方向（inbound/outbound）
- `is_private_ip`: 标记是否为私有IP地址

##### 4.4.1.2 会话级特征
- `session_duration`: 会话持续时间（秒）
- `total_packets`: 总数据包数
- `total_bytes`: 总字节数
- `packets_per_second`: 每秒数据包数
- `bytes_per_second`: 每秒字节数
- `inbound_frame_len`: 入向数据包长度统计
- `outbound_frame_len`: 出向数据包长度统计

##### 4.4.1.3 TCP 特征
- `tcp_flag_syn`: SYN 标志位
- `tcp_flag_ack`: ACK 标志位
- `tcp_flag_fin`: FIN 标志位
- `tcp_flag_rst`: RST 标志位
- `tcp_flag_psh`: PSH 标志位
- `tcp_flag_urg`: URG 标志位

##### 4.4.1.4 RTT 和延迟特征
- `rtt_ms`: 往返时间（毫秒）
- `rtt_ack_ms`: 基于ACK的RTT估计
- `avg_rtt_ms`: 平均RTT
- `min_rtt_ms`: 最小RTT
- `max_rtt_ms`: 最大RTT
- `std_rtt_ms`: RTT标准差
- `rtt_sample_count`: RTT样本数

### 4.4.2. `FeatureExtractor`: 特征提取协调器

### 4.5. 核心概念定义
- **流 (Flow)**: 指网络中具有相同五元组（源IP、源端口、目的IP、目的端口、协议）的单向数据包序列。
- **会话 (Session)**: 指两个端点之间的一个完整的、双向的逻辑通信。它由一个或多个相关的流组成（例如，一个从A到B的流和一个从B到A的流）。

`FeatureExtractor` 是特征工程模块的核心，它不亲自执行计算，而是像一个总指挥，按逻辑顺序调用一系列专门的“特征计算器” (`Calculator`)，实现从原始数据到高级上下文特征的逐层聚合。这种设计使得特征集可以灵活扩展，只需添加新的计算器即可。

**特征提取黄金流程 (Golden Pipeline):**

`FeatureExtractor` 严格遵循以下顺序，确保每一层特征都建立在更基础的层之上：

1.  **调用 `PacketCalculator` (L1)**: 对最原始的数据包进行分析，解码TCP标志位、IP选项等，为后续分析提供基础素材。
2.  **调用 `FlowCalculator` (L2)**: 将数据包聚合成单向流（5元组），计算流级别的统计特征，如持续时间、包/字节速率等。
3.  **调用 `SessionCalculator` (L2)**: 将相关的单向流（例如，客户端到服务器和服务器到客户端）聚合成一个双向会话，计算会话级的整体统计特征。
4.  **调用 `ProtocolCalculators` (L2)**: 对特定协议（如HTTP, DNS）的载荷进行深度解析，提取应用层特征。
5.  **调用 `HostCalculator` (L3)**: 在一个时间窗口内，聚合来自同一源/目的主机的所有会话，计算主机的行为特征，如会话创建频率、访问目标多样性等。
6.  **调用 `ProfileComparisonCalculator` (L3)**: 这是特征提取的最后一步，也是最关键的一步。它从 `ProfileStore` 获取该主机的历史画像，并将其与当前计算出的会-话/主机特征进行对比，生成最终的L3“画像对比”特征（如 `is_new_uri_for_ip`, `is_unusual_hour_for_ip`）。

通过这个流程，`FeatureExtractor` 最终为每个会话生成一个包含了从L1到L3所有信息的、丰富而立体的特征向量。

**核心实现示例:**

以下代码片段展示了`FeatureExtractor`如何与画像库及计算器协同工作，提取L2和L3特征：

```python
class FeatureExtractor:
    def __init__(self, config: dict):
        self.config = config
        self.features_config = config.get('features', {})
        self.enrichers = []
        self.calculators = []
        self._load_calculators()
        
    def extract_session_features(self, session_df: pd.DataFrame, client_ip: str):
        """
        提取会话级特征 (L2 + L3)
        
        Args:
            session_df: 包含会话数据的DataFrame
            client_ip: 客户端IP地址
            
        Returns:
            tuple: (特征字典, 历史档案)
        """
        # 1. 计算L2特征
        session_with_l2 = self._apply_l2_calculators(session_df)
        
        # 2. 获取历史档案
        historical_profile = self.profile_store.get_profile(client_ip)
        
        # 3. 计算L3特征 (与历史档案对比)
        l3_features = self.profile_comparison_calculator.calculate(
            session_features=session_with_l2,
            historical_profile=historical_profile
        )
        
        # 4. 合并特征并更新档案
        features = {**session_with_l2, **l3_features}
        self.profile_store.update_profile(client_ip, session_with_l2)
        
        return features, historical_profile
```

#### 4.6 核心组件

- **`features/extractor.py`**: 特征提取主类，负责：
  1. 数据预处理和标准化
  2. 按顺序调用特征计算器
  3. 合并所有特征为统一的DataFrame
  4. 处理特征缺失值和异常值

- **`features/calculators/`**: 特征计算器目录
  - **`base_calculator.py`**: 特征计算器基类，定义统一接口
  - **`packet_calculator.py`**: 包级特征
    - TCP标志位解析
    - 协议类型识别
    - 包长度统计
  - **`flow_calculator.py`**: 流级特征（核心）
    - 流持续时间
    - 包长统计（均值、方差、最大值、最小值）
    - 包到达间隔时间（IAT）统计
    - 流量速率（包/秒，字节/秒）
  - **`host_calculator.py`**: 主机级特征
    - 时间窗口内的连接数
    - 目的端口分布
    - 流量模式分析
  - **`protocol_calculators/`**: 协议特定特征
    - `http_calculator.py`: HTTP协议特征
    - `dns_calculator.py`: DNS查询分析
    - `tls_calculator.py`: TLS/SSL握手特征
    - `ssh_calculator.py`: SSH协议特征

#### 特征计算流程

1. **数据准备**：加载原始数据，进行基本清洗
2. **包级特征**：提取单个数据包的特征
3. **流级聚合**：按五元组（IP、端口、协议）聚合包特征
4. **主机级聚合**：按源/目的IP聚合流特征
5. **协议特定处理**：提取各应用层协议特有特征
6. **特征合并**：将所有特征合并为统一的特征矩阵

#### 性能优化

- 使用Pandas向量化操作
- 并行处理独立特征
- 内存高效的数据类型
- 增量特征计算

- **未来扩展**: 添加新的特征类别（例如，针对特定应用层协议如DNS或HTTP的特征），只需在 `calculators` 目录下创建一个新的计算器类即可，无需修改现有逻辑。

### 4.7. `enrichers/`: 数据富化层
数据富化是提升检测能力的关键。本系统设计了一个可插拔的富化层，用于为 IP 地址等实体添加上下文信息。

- **`enrichers/base_enricher.py`**: 定义了 `BaseEnricher` 抽象基类，所有具体的富化器都必须实现其 `enrich` 接口。

- **`enrichers/cache_manager.py`**: 提供一个缓存解决方案（例如，使用 SQLite 或磁盘缓存）。由于富化查询（特别是外部 API 调用）可能很慢或有成本，所有富化器都会通过这个管理器来缓存查询结果，从而极大地提高性能并持久化保存富化数据。

- **具体的富化器实现 (例如 `enrichers/geoip_enricher.py`)**: 每个富化器负责一种特定的信息查询。例如：
    - **`GeoIPEnricher`**: 使用本地 MaxMind GeoLite2 数据库查询 IP 的地理位置（国家、城市、ASN）。
    - **`ThreatIntelEnricher`**: 使用外部威胁情报平台的 API (如 AbuseIPDB) 查询 IP 是否为已知的恶意地址。
    - **`WhoisEnricher`**: 查询 IP 的 WHOIS 注册信息。

- **未来扩展**: 添加新的富化源只需在 `enrichers` 目录下创建一个新的富化器类并更新配置即可。

### 4.8. 高级分析层：个体画像与行为序列化

为了实现从“静态异常检测”到“上下文感知”的跨越，本系统引入了两个高级分析层：个体画像库和行为序列化器。

#### 4.8.1. `profiles/`: 动态客户端行为画像库

- **核心职责**: 作为系统的“长期记忆”，为每一个与服务交互的客户端IP建立并维护一个动态的行为档案。
- **技术实现**:
  - `profile_store.py`: `ProfileStore` 类负责与一个高性能键值存储（推荐使用 Redis，MVP阶段可使用内存字典）进行交互。它提供 `get_profile(ip)` 和 `update_profile(ip, data)` 等原子操作。
  - `profile_updater.py`: 一个独立的后台服务或线程，负责异步、安全地将会话分析结果更新到画像库中，避免阻塞实时检测流程。
- **画像内容**: 每个IP的画像是一个JSON对象，包含：
  - **访问模式**: `set_of_accessed_uris`, `set_of_user_agents`, `set_of_ja3s`
  - **时间模式**: `typical_hours_of_day` (分布向量)
  - **流量模式**: `avg_bytes_per_session`, `max_bytes_observed`

#### 4.8.2. `data/sequence_builder.py`: 行为序列构建器

- **核心职责**: 将离散的会话事件，串联成能被LSTM模型理解的“行为电影”。
- **工作流程**:
  - `SequenceBuilder` 为每个客户端IP维护一个固定长度（例如，最近20次）的会话特征向量队列。
  - 当一个新的会话特征向量产生时，它被推入对应IP的队列头部，最旧的向量则被移除。
  - 当需要进行LSTM分析时，它会提供这个完整的、填充/截断好的、标准化的序列数据（3D张量）。

### 4.9. `models/`: 双引擎异常检测架构

系统采用创新的双引擎、分层过滤模型，以实现速度与深度的最佳平衡。`ModelManager` 负责协调两个引擎的工作。

#### 引擎一: "巡警" - 孤立森林 (Isolation Forest)

- **角色**: 快速、广泛的实时初筛器。负责处理所有流量，瞬间识别出特征值极端的“暴力”攻击和明显的行为偏差。
- **输入**: L2+L3的扁平化特征向量。

#### 引擎二: "侦探" - LSTM自编码器 (LSTM Autoencoder)

- **角色**: 深度、上下文感知的序列分析器。专门用于分析通过初筛的、看似正常的流量，挖掘隐藏在操作顺序中的高级威胁。
- **输入**: 由`SequenceBuilder`提供的会话特征向量序列 (3D张量)。

#### 协作流程：分层过滤 (Layered Filtering)

1.  **初筛**: `ModelManager` 首先将特征向量送入孤立森林。如果得分超过高风险阈值，则直接判定为异常并生成告警。
2.  **序列构建**: 对于中低分事件，`ModelManager` 将其特征向量传递给 `SequenceBuilder`，更新对应IP的行为序列。
3.  **深度分析**: `SequenceBuilder` 将更新后的序列提供给 LSTM模型。
4.  **最终决策**: LSTM计算序列的重构误差。如果误差超过其自身的阈值，则生成一个更深层次的“序列异常”告警。

### 4.10. 示例：从原始数据包到最终特征向量

为了更具体地理解系统的数据处理流程，我们以一个简单的 TCP "三次握手" 过程为例，追踪数据从输入到输出的完整演变。

#### 4.10.1 阶段 1: 初始数据摄取与协议解析

数据首先由 `DataIngestor` 调用 `pcap_processor` 从 PCAP 文件中读取。`pcap_processor` 的核心职责是利用 `pyshark` 将原始、无结构的二进制数据包，解析成结构化的、包含丰富协议字段的 DataFrame。此时，DataFrame 的每一行代表一个数据包，每一列代表一个从包中提取出的关键字段。

下面，我们将针对不同协议，详细展示其关键字段的提取、处理与后续分析思路。

##### a. TCP 协议 (传输控制层)

TCP 是网络通信的基石，其连接建立、数据传输和连接终止的行为模式是网络异常检测的基础。

**示例 (TCP 三次握手):**

| timestamp           | src_ip      | dst_ip      | src_port | dst_port | protocol | frame_len | tcp_flags |
|---------------------|-------------|-------------|----------|----------|----------|-----------|-----------|
| 2023-10-01 12:00:00 | 1.2.3.4     | 10.0.0.5    | 12345    | 443      | TCP      | 66        | 0x002     |
| 2023-10-01 12:00:01 | 10.0.0.5    | 1.2.3.4     | 443      | 12345    | TCP      | 66        | 0x012     |
| 2023-10-01 12:00:01 | 1.2.3.4     | 10.0.0.5    | 12345    | 443      | TCP      | 54        | 0x010     |

- **关键字段提取**: `pcap_processor` 从 TCP 层提取 `tcp.flags` (标志位), `tcp.srcport` (源端口), `tcp.dstport` (目的端口), `tcp.seq` (序列号), `tcp.ack` (确认号) 等。
    - `tcp_flags` 是一个十六进制数，包含了 SYN, ACK, FIN, RST 等所有标志位的组合信息。
- **处理与判断**: `pcap_processor` 将这些字段直接填入 DataFrame。
- **再处理思路 (`PacketCalculator`, `FlowCalculator`)**: 
    - `PacketCalculator` 会对 `tcp_flags` 进行“解码”，将其转换为多个独立的布尔型特征（如 `tcp_flag_syn`, `tcp_flag_ack`），使得模型可以直接理解每个包的具体意图。
    - `FlowCalculator` 则会使用五元组（IP、端口、协议）将这些独立的包串联成“流”，并基于 `timestamp` 和 `tcp_seq` 等信息计算流的持续时间、包速率、字节速率等高级统计特征。

##### b. HTTP 协议 (应用层)

HTTP 流量的分析对于检测 Web 攻击、恶意爬虫和非法数据外传至关重要。

**示例 (一个 HTTP GET 请求):**

| ... | protocol | http_request_method | http_request_uri       | http_user_agent                | http_host | http_response_code |
|-----|----------|---------------------|------------------------|--------------------------------|-----------|--------------------|
| ... | HTTP     | GET                 | /login.php?user=admin  | Mozilla/5.0 (Windows NT 10.0)  | example.com | 200                |

- **关键字段提取**: 当 `pcap_processor` 检测到 TCP 端口为 80 或在 TCP 载荷中识别出 HTTP 协议时，它会进一步解析应用层数据，提取 `http.request.method`, `http.request.uri`, `http.user_agent`, `http.host` 以及 `http.response_code` (HTTP 响应的状态码) 等字段。
- **处理与判断**: 如果一个包是 HTTP 请求，这些字段会被填充；如果不是（例如，只是一个 TCP ACK 包），这些字段将为 `NaN`。
- **再处理思路 (`HttpCalculator`)**: 
    - 对 `http_request_method` 进行独热编码，生成 `http_method_get`, `http_method_post` 等特征。
    - 计算 `http_request_uri` 的长度 (`http_uri_length`) 和信息熵 (`http_uri_entropy`)。攻击载荷（如 SQL 注入）通常会使 URI 变得异常长或包含混乱的字符，从而导致熵值异常。

##### c. SSH 协议 (应用层)

虽然 SSH 流量是加密的，无法看到内部指令，但其连接建立阶段的元数据对于检测暴力破解或中间人攻击非常有价值。

**示例 (SSH 客户端与服务器版本协商):**

| ... | protocol | ssh_protocol | ssh_server_version      | ssh_client_version      |
|-----|----------|--------------|-------------------------|-------------------------|
| ... | SSH      | 2.0          | OpenSSH_8.2p1 Ubuntu-4  | libssh-0.9.3            |

- **关键字段提取**: `pcap_processor` 在 TCP 端口 22 上查找 SSH 协议，并提取其握手信息，如 `ssh.protocol` (协议版本), `ssh.server_version` (服务器软件), `ssh.client_version` (客户端软件)。
- **处理与判断**: 这些字段只在 SSH 握手包中存在。
- **再处理思路 (`SshCalculator`)**: 
    - 检查 `ssh_protocol` 是否为已知的弱版本（如 SSHv1）。
    - 将 `ssh_server_version` 和 `ssh_client_version` 与已知存在漏洞的版本库进行比对，以识别正在使用脆弱软件的连接。

##### d. SQL (TDS) 协议 (应用层)

直接分析数据库查询流量是检测 SQL 注入、数据窃取等内部威胁的强大手段。

**示例 (一个通过 TDS 协议传输的 SQL 查询):**

| ... | protocol | sql_query                                           |
|-----|----------|-----------------------------------------------------|
| ... | TDS      | SELECT * FROM users WHERE id = '1' OR '1'='1'       |

- **关键字段提取**: `pcap_processor` 在 TCP 端口 1433 (MS-SQL) 上寻找 TDS (Tabular Data Stream) 协议，并从中直接提取出 `tds.query` 字段，即原始的 SQL 查询语句。
- **处理与判断**: 只有包含 SQL 查询的数据包才会填充 `sql_query` 字段。
- **再处理思路 (`SqlCalculator`)**: 
    - 计算 `sql_query` 的长度和熵，类似于对 URI 的分析。
    - **核心功能**: 将查询语句与一个可配置的、包含高危关键词（如 `UNION SELECT`, `DROP TABLE`, `'1'='1'`）的列表进行正则匹配。一旦匹配成功，就会生成一个强烈的告警信号 `sql_contains_suspicious_keywords`。

##### e. DNS 协议 (应用层)

DNS 是一个关键的攻击向量，常被用于数据泄露和 C&C 通信。我们提取其核心查询字段。

**示例 (一个 DNS 查询):**

| ... | protocol | dns_qry_name | dns_qry_type |
|-----|----------|--------------|--------------|
| ... | DNS      | example.com  | 1 (A)        |

- **关键字段提取**: `pcap_processor` 在 UDP 端口 53 上寻找 DNS 协议，并从中直接提取出 `dns_qry_name` (查询的域名) 和 `dns_qry_type` (查询的记录类型)。
- **处理与判断**: 只有包含 DNS 查询的数据包才会填充这些字段。
- **再处理思路 (`DnsCalculator`)**:
    - 计算 `dns_qry_name` 的长度和信息熵，高熵或超长域名可能是 DGA (Domain Generation Algorithm) 的迹象。
    - 监控 `dns_qry_type` 为 `TXT` 或 `NULL` 的异常请求，这些常被用于 DNS 隧道。

##### f. TLS/SSL 协议 (应用层)

即使流量被加密，其握手过程中的元数据也能暴露威胁。我们通过解析 `Client Hello` 消息来构建 **JA3 指纹**，这是一种识别特定客户端（如恶意软件）的强大技术。

**示例 (一个 TLS/SSL 握手):**

| ... | protocol | tls_ja3                                                              |
|-----|----------|----------------------------------------------------------------------|
| ... | TLSv1.2  | 771,4865-4866-4867-49195-49199-49196-49200-52393-52392...             |

- **关键字段提取**: `pcap_processor` 检查 TLS/SSL 握手包，如果是 `Client Hello` 类型，则提取 SSL 版本、加密套件、扩展列表等字段，并将其拼接成 `tls_ja3` 指纹字符串。
- **处理与判断**: 该字段仅在 TLS `Client Hello` 包中生成。
- **再处理思路 (`TlsCalculator`)**:
    - 将提取出的 `tls_ja3` 指纹与已知的恶意软件 JA3 指纹库（如 abuse.ch 的 JA3/S Fingerprint Blacklist）进行比对。
    - 统计特定 `tls_ja3` 指纹出现的频率，异常的、罕见的指纹可能指向可疑活动。

#### 阶段 2: 数据富化

`FeatureExtractor` 调用 `Enricher`，为 IP 地址添加上下文信息。注意 `10.0.0.5` 是私有地址，所以没有富化信息。

| src_ip      | ... | src_ip_geo_country | src_ip_asn_org |
|-------------|-----|--------------------|----------------|
| 1.2.3.4     | ... | United States      | Google LLC     |
| 10.0.0.5    | ... | Private            | Private        |
| 1.2.3.4     | ... | United States      | Google LLC     |

#### 阶段 3: 分层特征计算：从“是什么”到“像什么”

这是特征工程的核心阶段，其目标是**将描述数据包“是什么”的静态字段，转化为描述“行为模式像什么”的动态特征**。这些高层次的“行为特征”（如数据包发送方向、频率、大小、报错等）无法从单个数据包中看出，必须在更高的维度（流或主机）上进行聚合与计算。这主要由 `FlowCalculator` 和 `HostCalculator` 完成。

接下来，数据依次通过三个特征计算器：

**1. `PacketCalculator` (包级): 解码基础意图**

它解析 `tcp_flags` 字段，生成独立的布尔标志位。这一步是后续所有行为分析的基础。

- **主要特征**: `tcp_flag_syn`, `tcp_flag_ack`, `tcp_flag_fin`, `tcp_flag_rst`。
- **针对攻击与判断逻辑**:
    - **攻击类型**: **端口扫描 (Port Scanning)**，如 SYN 扫描、FIN 扫描、XMAS 扫描。
    - **判断逻辑**: 攻击者通过发送非正常的 TCP 标志组合来探测目标端口的状态。例如，一个源 IP 在短时间内向大量不同的目标端口发送了大量只设置了 `SYN` 位的包，而没有收到相应的 `SYN/ACK` 回应，这便是 **SYN 扫描** 的典型特征。同样，只设置了 `FIN` 位的包可以用于执行 **FIN 扫描**。

| ... | tcp_flags | tcp_flag_syn | tcp_flag_ack |
|-----|-----------|--------------|--------------|
| ... | 0x002     | True         | False        |
| ... | 0x012     | True         | True         |
| ... | 0x010     | False        | True         |

**2. `FlowCalculator` (流级): 刻画会话行为**

`FlowCalculator` 是最重要的计算器之一，它负责将会话（Flow）作为一个整体进行分析，提取其“行为特征”。

- **方向特征 (Direction)**:
    - **针对攻击与判断逻辑**:
        - **攻击类型**: **DDoS 攻击、数据泄露 (Data Exfiltration)**。
        - **判断逻辑**: 正常流量通常具有一定的对称性。当**正向（客户端->服务器）的包数或字节数远大于反向**时，可能表示大量的伪造请求正在涌向服务器，这是 **DDoS 攻击** 的征兆。反之，当**反向（服务器->客户端）的字节数异常地远大于正向**时，可能意味着有大量的内部数据正在被非法传出，这是 **数据泄露** 的关键特征。
- **频率特征 (Frequency)**:
    - **针对攻击与判断逻辑**:
        - **攻击类型**: **暴力破解 (Brute-force)、僵尸网络心跳 (Botnet C&C)、自动化扫描**。
        - **判断逻辑**: 机器生成的恶意流量通常具有高度规律的“节拍”。一个**极小且稳定的包间到达时间标准差 (`flow_iat_std`)** 是其最显著的特征。例如，**暴力破解**脚本会以固定的高频率尝试登录；**僵尸网络**的受控端会以精确的时间间隔向其控制服务器发送“心跳”包。这些都与正常人类用户不规律的、突发性的网络行为形成鲜明对比。
- **大小特征 (Size)**:
    - **针对攻击与判断逻辑**:
        - **攻击类型**: **缓冲区溢出攻击 (Buffer Overflow)、隐蔽信道 (Covert Channel)**。
        - **判断逻辑**: 不同的应用层协议具有不同的包长分布。一个流中如果出现**异常大的数据包 (`flow_pkt_len_max`)**，可能是在尝试触发服务器的**缓冲区溢出**漏洞。反之，如果流量伪装成正常协议，但其包长却呈现出非典型的、**高度一致的分布（极小的 `flow_pkt_len_std`）**，则可能是在利用**隐蔽信道**进行秘密通信。
- **报错与重传 (Errors)**:
    - **针对攻击与判断逻辑**:
        - **攻击类型**: **端口扫描、网络劫持、中间人攻击**。
        - **判断逻辑**: 错误是异常最直接的体现。一个源 IP 的活动如果在网络中引发了**大量的 TCP `RST` 包**，意味着它正在持续地尝试连接大量未开放的端口，这是**端口扫描**最可靠的证据之一。而一个流内出现**大量的 TCP 重传**，除了表示网络不稳定外，也可能是**中间人攻击**者正在干扰或篡改通信，导致数据包校验失败。

**示例合并后**: DataFrame 中的所有三行都会被添加上丰富的流特征字段。

| ... | flow_duration_seconds | flow_pkt_count | flow_pkts_per_second | flow_fwd_pkt_count | flow_bwd_pkt_count | flow_iat_mean | flow_pkt_len_std |
|-----|-----------------------|----------------|----------------------|--------------------|--------------------|---------------|------------------|
| ... | 1.0                   | 3              | 3.0                  | 2                  | 1                  | 0.5           | 6.0              |
| ... | 1.0                   | 3              | 3.0                  | 2                  | 1                  | 0.5           | 6.0              |
| ... | 1.0                   | 3              | 3.0                  | 2                  | 1                  | 0.5           | 6.0              |

**3. `HttpCalculator` (应用层): 解剖Web流量**

- **主要特征**: `http_uri_length`, `http_uri_entropy`, `http_method_*` (独热编码)。
- **针对攻击与判断逻辑**:
    - **攻击类型**: **SQL 注入、跨站脚本 (XSS)、命令注入、目录遍历**。
    - **判断逻辑**: 几乎所有的 Web 攻击都依赖于将恶意代码或指令嵌入到正常的 HTTP 请求中。这种嵌入行为必然会改变请求的形态：
        - **`http_uri_length`**: 注入的攻击载荷通常会使 URI 的长度变得**异常地长**。
        - **`http_uri_entropy`**: 为了绕过简单的防火墙规则，攻击载荷常常被编码（如 Base64, Hex），这使得 URI 中充满了无规律的、混乱的字符，从而导致其**信息熵异常地高**。
        - **`http_method_*`**: 结合 URI 分析，可以发现例如在 `GET` 请求中出现了通常用于数据库修改的 SQL 关键词等不匹配行为。

假设第一个包是一个 HTTP GET 请求。该计算器会提取 HTTP 信息，并进行独热编码和衍生计算。

| ... | http_request_method | http_uri_length | http_uri_entropy | http_method_get |
|-----|---------------------|-----------------|------------------|-----------------|
| ... | GET                 | 25              | 4.8              | 1               |
| ... | NaN                 | 0               | 0.0              | 0               |
| ... | NaN                 | 0               | 0.0              | 0               |

**4. `HostCalculator` (主机级): 描绘实体画像**

`HostCalculator` 在比流更高的维度上运作。它不再关注单个会话，而是**为每个独立的主机（IP 地址）建立一个短时间内的行为画像**。它通过在固定的时间窗口（例如，1秒、10秒）内聚合一个源 IP 或目的 IP 的所有活动来实现。

- **连接模式**:
    - **针对攻击与判断逻辑**:
        - **攻击类型**: **横向移动 (Lateral Movement)、网络扫描 (Network Scanning)**。
        - **判断逻辑**: 一个正常的主机在短时间内的通信模式是相对固定的。如果一个源 IP 在一个极短的时间窗口内（如1秒），突然开始**连接大量不同的目的 IP 或目的端口**，这便是**网络扫描**或攻击者在内网中进行**横向移动**探测的强烈信号。
- **角色行为**:
    - **针对攻击与判断逻辑**:
        - **攻击类型**: **分布式拒绝服务攻击 (DDoS)**。
        - **判断逻辑**: 一个服务器在正常情况下被访问的源 IP 数量会遵循一定的模式（如潮汐效应）。如果一个目的 IP 在短时间内，被**远超正常基线的、海量的、来自不同地理位置的源 IP 同时连接**，那么它极有可能正在遭受 **DDoS 攻击**。
- **流量概况**: 在1秒内，一个主机总共发送/接收了多少流量？这有助于识别流量异常的主机。

这些主机级的特征为我们提供了超越单个连接的“上帝视角”，能够发现更大范围、更长时间跨度的协同攻击或异常模式。

### 高级攻击模式与检测策略

除了上述由基础计算器直接识别的攻击外，我们的分层特征系统也为检测更隐蔽、更高级的攻击手法提供了基础。以下是一些额外可以被检测的攻击类型及其特征：

#### 1. “慢速”攻击 (Slow and Low Attacks)

这类攻击的核心思想不是用巨大的流量淹没目标，而是通过**极慢的交互**来耗尽服务器的连接资源。

*   **攻击类型**: **Slowloris, Slow HTTP POST/GET**
*   **攻击手法**: 攻击者与服务器建立一个正常的 HTTP 连接，但故意以极慢的速度发送请求数据（例如，每隔几分钟才发送一个字节）。由于请求一直没有发送完毕，服务器会一直为这个连接保留一个线程/进程，当成百上千个这样的“慢速连接”被建立时，服务器的所有连接资源都会被耗尽，无法再响应任何正常用户的请求。
*   **流量特征**:
    *   **极长的流持续时间 (`flow_duration_seconds`)**: 连接可以持续数小时甚至数天。
    *   **极低的数据传输速率 (`flow_bytes_per_second`)**: 流中几乎没有有效的数据载荷。
    *   **正常的 TCP 行为**: 连接本身是合法的，没有大量的 `RST` 包或重传。
*   **检测思路**: 在 `FlowCalculator` 中，寻找那些**持续时间极长，但包数和字节数却极少**的流。这是一个非常强烈的异常信号。

#### 2. 应用层暴力破解

我们之前讨论的暴力破解主要基于连接频率，但更精准的检测需要深入到应用层。

*   **攻击类型**: **Web 登录爆破, FTP/SSH 密码猜测**
*   **攻击手法**: 攻击者针对一个特定的登录接口（如网站的 `/login` 页面），以非常高的频率提交不同的用户名和密码组合。
*   **流量特征**:
    *   **高频率的请求**: 一个源 IP 在短时间内向同一个目的 IP 的同一个端口、同一个 URI 发送大量请求。
    *   **大量的失败响应**: 服务器会返回大量的“认证失败”响应（例如，HTTP 状态码 `401 Unauthorized` 或 `403 Forbidden`），最终可能伴随着一个“成功”响应（HTTP `200 OK`）。
    *   **请求-响应大小固定**: 失败的登录尝试，其请求和响应的大小通常是固定的。
*   **检测思路**: 在 `HttpCalculator` 中，不仅要分析请求，还要**分析响应码**。统计在短时间内，从同一个源 IP 到同一个目标 URI 的 `4xx` 状态码的频率和数量。

#### 3. DNS 隧道 (DNS Tunneling)

这是最高级的隐蔽通信手段之一，攻击者利用无处不在的 DNS 协议来建立一个秘密的通信隧道，用于**数据泄露**或**僵尸网络控制 (C&C)**。

*   **攻击类型**: **DNS 数据泄露, DNS C&C 通信**
*   **攻击手法**: 攻击者将要窃取的数据进行编码（如 Base64），并将其作为超长子域名，向自己控制的恶意 DNS 服务器发起查询。例如，将 `secret_data` 编码后变成 `c2VjcmV0X2RhdGE=`，然后查询 `c2VjcmV0X2RhdGE=.malicious-domain.com`。通过DNS响应，C&C 服务器也可以向受控主机下发指令。
*   **流量特征**:
    *   **超长的 DNS 查询名**: 查询的域名长度远超正常水平。
    *   **查询名的高信息熵**: 编码后的数据看起来是无意义的随机字符串，因此信息熵很高。
    *   **非标准的查询类型**: 大量使用 `TXT` 或 `CNAME` 记录来传输数据，而不是常见的 `A` 或 `AAAA` 记录。
    *   **高频率的 DNS 查询**: 一个主机向某个特定域名发起远超正常频率的查询。
*   **检测思路**: 需要一个专门的 `DnsCalculator`，用于解析 DNS 协议，计算查询名的**长度、信息熵、查询类型分布**等特征。

#### 4. 加密流量中的威胁 (Threats in Encrypted Traffic)

越来越多的恶意软件使用标准的 TLS/SSL 加密来隐藏其 C&C 通信。虽然我们无法解密载荷，但元数据依然可以暴露它们。

*   **攻击类型**: **基于 TLS 的僵尸网络 C&C, 加密勒索软件通信**
*   **流量特征**:
    *   **TLS/SSL 指纹 (JA3/JA3S)**: 每个客户端在发起 TLS 连接时，其 `Client Hello` 包中的加密套件、扩展等参数组合会形成一个独特的指纹 (JA3)。已知的恶意软件通常使用固定的网络库，因此会留下特定的 JA3 指纹。
    *   **证书异常**: 使用自签名证书、证书有效期过短/过长、证书颁发者不常见等。
    *   **连接模式**: 即使流量是加密的，其连接的**周期性、数据包大小分布、连接时长**等行为特征依然可以被 `FlowCalculator` 捕捉，并与已知恶意软件的行为模式进行匹配。
*   **检测思路**: 需要一个 `TlsCalculator` 来解析 TLS 握手过程，提取 **JA3/JA3S 指纹**和**证书信息**。同时，`FlowCalculator` 提取的行为特征也至关重要。

#### 阶段 4: 最终特征向量

所有处理完成后，我们得到一个非常宽的 DataFrame。每一行都包含了来自所有层级的特征，为模型提供了对每个数据包的 360 度全景视图。这个最终的特征向量被送入 `ModelManager` 进行异常检测。

**(展示部分最终字段)**

| src_ip  | dst_ip   | ... | src_ip_geo_country | tcp_flag_syn | flow_pkt_count | src_host_pkt_count_win |
|---------|----------|-----|--------------------|--------------|----------------|------------------------|
| 1.2.3.4 | 10.0.0.5 | ... | United States      | True         | 3              | 2                      |
| 10.0.0.5| 1.2.3.4  | ... | Private            | True         | 3              | 1                      |
| 1.2.3.4 | 10.0.0.5 | ... | United States      | False        | 3              | 2                      |

- **`models/base.py`**: 定义了一个 `BaseModel` 抽象基类。所有模型都必须继承这个类并实现其定义的统一接口（`fit` 和 `predict`）。这确保了不同算法之间的一致性和互操作性。

- **`models/model_manager.py`**: `ModelManager` 类是模型的中央协调器。它会读取配置文件中的 `model.type` 字段，并动态地从相应的模块（例如 `isolation_forest.py`）加载模型。它还负责处理模型的训练、预测、保存和加载。

- **`models/<algorithm_name>.py`**: 每种异常检测算法都在其自己的文件中实现（例如 `isolation_forest.py`, `one_class_svm.py`）。每个文件都包含一个继承自 `BaseModel` 的类，并实现了特定于该算法的训练和预测逻辑。

#### 如何添加新算法

要添加一个新的异常检测算法（例如，`my_new_algorithm`），请按照以下步骤操作：

1.  **创建模型文件**: 在 `src/traffic_detect/models/` 目录下创建一个新文件 `my_new_algorithm.py`。
2.  **实现模型类**: 在该文件中，创建一个继承自 `BaseModel` 的类（例如 `MyNewAlgorithmModel`）。实现 `__init__`、`fit` 和 `predict` 方法。
3.  **更新配置**: 在您的 `config.yaml` 文件中，将 `model.type` 设置为 `my_new_algorithm`，并根据需要配置其 `params`。

`ModelManager` 将自动发现并加载您的新模型，无需修改任何现有代码。

### 4.9. `visualization/dashboard.py`: 报告
- **职责**：生成易于人类阅读的分析结果报告。
- **设计**：`ResultVisualizer` 类接收特征数据和预测，以创建摘要报告。目前，它生成一个简单的 HTML 报告，但可以扩展以使用 `matplotlib` 或 `plotly` 等库生成复杂的图表。

### 4.10. 数据处理流程

端到端的数据流水线被设计为高度模块化和标准化的流程：

1.  **收集 (Collect)**：`DataCollector` 识别 `data/raw/` 或其他指定位置的原始数据文件（如 PCAP, NetFlow CSV 等）。
2.  **摄取与标准化 (Ingest & Standardize)**：`DataIngestor` 为每个原始文件选择合适的解析器（如 `PcapProcessor`）。解析器将原始数据转换为一个**标准格式的 DataFrame**，这个 DataFrame 是后续所有步骤的统一输入。
3.  **富化与特征提取 (Enrich & Extract)**：`FeatureExtractor` 首先将标准化的 DataFrame 中的 IP 地址发送到数据富化层，获取地理位置、威胁情报等上下文信息。然后，它将这些新信息与原始数据结合，计算出最终用于模型训练和检测的特征集。
5.  **检测 (Detect)**：`ModelManager` 使用加载的算法模型，在特征数据上进行训练或预测异常。
6.  **可视化 (Visualize)**：`ResultVisualizer` 使用特征和预测结果生成分析报告。


### 9.5 数据存储与管理策略

随着数据量的增长，有效的存储和管理至关重要。本系统规划了以下策略：

#### 9.5.1 存储抽象层
- **设计**: 引入一个 `StorageManager` 类，作为统一的文件访问接口。所有模块（如 `DataIngestor`, `ModelManager`）都通过它来读写数据，而不是直接操作文件系统路径。
- **优点**: 这种设计将核心逻辑与具体的存储实现（本地文件系统、云存储）解耦，使得未来切换或扩展存储后端变得容易。

#### 9.5.2 可扩展的存储后端
- **当前**: 默认使用本地文件系统，并将结构化数据存储为高效的 Parquet 格式。
- **未来**: 计划通过 `StorageManager` 支持云存储后端（如 AWS S3, Google Cloud Storage）。用户将能够通过修改配置文件，无缝地将数据存储在云端，以获得更好的可扩展性、可靠性和成本效益。

#### 9.5.3 数据生命周期管理
- **规划**: 在配置中增加数据保留策略（Data Retention Policy），允许系统自动清理或归档过期的数据。例如，可以配置自动删除超过30天的报告，或将超过90天的原始数据归档到低成本的“冷”存储中。

### 5.4. 数据溯源与版本控制
- **挑战**: 确保分析结果的可复现性，需要追踪数据、代码和模型之间的关系。
- **规划**: 预留接口，为未来集成元数据存储（如 SQLite 数据库）或专门的数据版本控制工具（如 DVC）做准备。这将记录每次运行的上下文信息（如代码版本、配置文件、输入数据哈希等），从而实现端到端的溯源。



## 8. Arkime 数据源集成

### 8.1 概述
Arkime（前身为Moloch）是一个大规模数据包捕获和搜索工具，本系统通过以下方式集成Arkime：

#### 8.1.1 主要功能
- **Arkime API 集成**：通过REST API与Arkime服务器通信
- **SPI 数据支持**：处理Arkime会话数据（Session Packet Index）
- **流式处理**：支持增量数据拉取和实时处理
- **字段映射**：将Arkime字段映射到统一的数据模型

#### 8.1.2 数据收集流程
1. 通过Arkime API查询会话数据
2. 将原始JSON响应转换为内部数据格式
3. 提取关键字段（源/目标IP、端口、协议等）
4. 计算会话级指标（字节数、包数、持续时间等）
5. 与现有PCAP处理管道集成

#### 8.1.3 配置示例
```yaml
arkime:
  enabled: true
  server: "https://arkime.example.com"
  api_key: "your_api_key_here"
  fetch_interval: 300  # 数据拉取间隔（秒）
  lookback: 3600       # 每次查询的时间范围（秒）
  fields:              # 要提取的Arkime字段
    - id
    - firstPacket
    - lastPacket
    - src
    - dst
    - srcPort
    - dstPort
    - protocols
    - bytes
    - packets
```

## 9. 未来工作与路线图

为了将新的双引擎架构从概念设计转化为可部署的系统，我们规划了以下分阶段的实施路径：

#### 阶段一：基础建设与画像 MVP (Minimum Viable Product)
*   **目标**: 搭建个体画像系统的基础，并将其作为 L3 特征融入现有检测流程。
*   **关键任务**:
    1.  **实现 `ProfileStore`**: 完成画像存储模块，初期可使用内存字典作为后端，以快速验证功能。
    2.  **实现 `ProfileUpdater`**: 开发一个异步更新器，安全地将会话分析结果写入画像库，避免阻塞主检测流程。
    3.  **集成 L3 特征**: 将画像对比结果（如 `is_new_uri_for_ip`）作为新的 L3 特征，输入给现有的孤立森林模型，初步提升其上下文感知能力。
    4.  **单元测试**: 为 `profiles` 模块编写基础的单元测试，确保其稳定可靠。

#### 阶段二：序列构建与 LSTM 集成
*   **目标**: 引入 LSTM 引擎，实现从静态检测到序列分析的跨越。
*   **关键任务**:
    1.  **实现 `SequenceBuilder`**: 完成行为序列构建器，能够为每个 IP 维护一个固定长度的会话特征序列。
    2.  **实现 `LSTMAutoencoder`**: 开发 LSTM 自编码器模型，包括其训练和预测逻辑。
    3.  **改造 `ModelManager`**: 升级模型管理器，使其支持“孤立森林初筛 + LSTM 复核”的双引擎协作流程。
    4.  **开发训练管道**: 为 LSTM 模型建立一个离线的训练、评估和调优管道。

#### 阶段三：生产化与性能优化
*   **目标**: 确保新架构的性能和稳定性，为部署到生产环境做准备。
*   **关键任务**:
    1.  **持久化 `ProfileStore`**: 将画像库的后端从内存字典迁移到高性能的键值存储（如 Redis），确保画像数据持久化且可扩展。
    2.  **优化序列管理**: 对 `SequenceBuilder` 进行性能和内存优化，确保能高效处理大规模 IP 的序列数据。
    3.  **监控与日志**: 为双引擎模型和画像库添加详细的监控指标和日志，以便于问题排查和性能调优。
    4.  **模型版本控制**: 建立一套有效的模型版本管理和热更新机制。

#### 阶段四：高级功能与可解释性
*   **目标**: 提升检测结果的可用性，并探索更前沿的分析技术。
*   **关键任务**:
    1.  **可视化序列异常**: 在分析报告中增加新的可视化模块，用于直观展示导致 LSTM 报警的异常行为序列。
    2.  **增强可解释性 (XAI)**: 探索如 SHAP 或 LIME 等技术，尝试解释 LSTM 模型做出异常判断的关键特征和时间步，提升告警的可信度和可操作性。
    3.  **特征迭代**: 基于在真实数据上的运行结果，持续迭代和优化为两个引擎输入的特征集。

### 5. 会话分析与特征提取实现

#### 5.2.1 特征列表
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"

### 5. 会话分析与特征提取实现

#### 5.2.1 特征列表

`SessionCalculator` 计算以下几类特征：

1.  **基础统计特征**
    *   `total_packets`: 会话总包数
    *   `total_bytes`: 会话总字节数
    *   `avg_packet_size`: 平均包大小
    *   `std_packet_size`: 包大小标准差

2.  **时间相关特征**
    *   `session_duration`: 会话持续时间
    *   `session_active_time`: 会话活跃时间（所有流持续时间之和）
    *   `session_idle_time`: 会话空闲时间
    *   `active_idle_ratio`: 活跃/空闲时间比

3.  **方向与不对称特征**
    *   `inbound_frame_len_count` / `outbound_frame_len_count`: 入/出方向的包数量
    *   `inbound_frame_len_sum` / `outbound_frame_len_sum`: 入/出方向的字节总量
    *   `session_bytes_ratio`: 出/入方向字节比
    *   `session_packets_ratio`: 出/入方向包数量比

4.  **行为与速率特征**
    *   `small_packet_count`: 小数据包（<64字节）数量
    *   `small_packet_ratio`: 小数据包比率
    *   `packets_per_second`: 每秒包数
    *   `bytes_per_second`: 每秒字节数

#### 4.2.2 核心代码

以下是 `calculate` 方法的核心逻辑，展示了如何计算这些复杂的会话级特征。

```python
# 会话特征提取 (session_calculator.py)
def calculate(self, df: pd.DataFrame) -> pd.DataFrame:
    # ... 省略输入验证和准备步骤 ...

    # 1. 生成会话键和方向
    df['session_key'] = df.apply(self._get_session_key, axis=1)
    df['direction'] = df.apply(self._get_direction, axis=1)
    
    # 2. 计算基础会话统计
    session_stats = df.groupby('session_key').agg(
        total_packets=('frame_len', 'count'),
        total_bytes=('frame_len', 'sum'),
        # ... 其他基础聚合 ...
    )

    # 3. 计算方向性统计
    for direction in ['inbound', 'outbound']:
        dir_df = df[df['direction'] == direction]
        if not dir_df.empty:
            dir_stats = dir_df.groupby('session_key').agg(
                frame_len_count=('frame_len', 'count'),
                frame_len_sum=('frame_len', 'sum')
            )
            session_stats = session_stats.join(dir_stats.add_prefix(f'{direction}_'))

    # 4. 计算不对称和比率特征
    session_stats['session_bytes_ratio'] = session_stats['outbound_frame_len_sum'] / (session_stats['inbound_frame_len_sum'] + 1e-6)
    session_stats['session_packets_ratio'] = session_stats['outbound_frame_len_count'] / (session_stats['inbound_frame_len_count'] + 1e-6)

    # 5. 计算活跃/空闲时间
    active_time_stats = df.groupby('session_key')['flow_duration_seconds'].sum()
    session_stats['session_active_time'] = active_time_stats
    session_stats['session_idle_time'] = session_stats['session_duration'] - session_stats['session_active_time']

    # 6. 计算速率特征
    session_stats['packets_per_second'] = session_stats['total_packets'] / (session_stats['session_duration'] + 1e-6)
    session_stats['bytes_per_second'] = session_stats['total_bytes'] / (session_stats['session_duration'] + 1e-6)

    # ... 合并结果并返回 ...
    return df.merge(session_stats.reset_index(), on='session_key', how='left')
```

### 4.3 特征提取管道



### 4.4 性能优化与扩展

#### 4.4.1 性能优化
- **批量处理**: 使用Pandas向量化操作
- **内存管理**: 及时释放不再需要的数据
- **并行处理**: 支持多会话并行处理

#### 4.4.2 扩展性设计
- **插件架构**: 支持动态加载特征计算器
- **配置驱动**: 通过YAML配置调整特征提取参数
- **可扩展性**: 易于添加新的特征类型和计算逻辑

### 4.5. LSTM 输入特征字段

为了让LSTM模型能有效地学习“行为语法”，其输入的序列特征向量应包含以下经过标准化处理的数值型字段：

#### 第一梯队 (核心行为):
- **流量统计**: `flow_duration_seconds`, `flow_pkt_count`, `flow_byte_count`, `flow_pkts_per_second`, `flow_bytes_per_second`
- **方向性**: `flow_fwd_pkt_count`, `flow_bwd_pkt_count`, `session_bytes_ratio`
- **时间动态**: `flow_iat_mean`, `flow_iat_stddev`
- **包大小分布**: `flow_pkt_len_mean`, `flow_pkt_len_std`

#### 第二梯队 (应用层上下文):
- **HTTP**: `http_method_*` (独热编码后), `http_response_code_*` (独热编码后), `http_uri_length`, `http_uri_entropy`
- **DNS**: `dns_query_length`, `dns_query_entropy`, `dns_qry_type_*` (独热编码后)
- **TLS**: `tls_ja3` (经过频率编码或目标编码后的数值)

#### 第三梯队 (个体画像对比):
- `is_new_uri_for_ip` (转换为 0/1)
- `is_unusual_hour_for_ip` (转换为 0/1)
- `is_new_user_agent_for_ip` (转换为 0/1)
- ... (其他所有L3对比特征)
