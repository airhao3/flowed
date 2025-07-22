# Flowed: Network Traffic Analysis & Anomaly Detection

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Flowed 是一个基于 Python 的网络流量分析与异常检测系统，使用机器学习算法自动识别网络流量中的异常行为。

## ✨ 功能特性

### 核心功能
- 🎯 支持 PCAP/PCAPNG 格式的网络流量文件解析
- 🔍 多维度特征提取与工程化处理
- 🤖 基于 Isolation Forest 的异常流量检测
- 📊 交互式可视化分析报告

### 技术亮点
- 🚀 高性能特征计算管道
- 📈 可扩展的模型架构
- 🎨 丰富的可视化组件
- ⚙️ 灵活的配置系统
- 📝 详细的日志记录

## 🚀 快速开始

### 环境要求
- Python 3.8+
- pip 或 uv

### 安装步骤

1. 克隆仓库：
   ```bash
   git clone git@github.com:airhao3/flowed.git
   cd flowed
   ```

2. 创建并激活虚拟环境：
   ```bash
   # 使用 venv
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   .venv\Scripts\activate    # Windows

   # 或者使用 uv (推荐)
   uv venv
   source .venv/bin/activate  # Linux/Mac
   .venv\Scripts\activate    # Windows
   ```

3. 安装依赖：
   ```bash
   # 使用 pip
   pip install -r requirements.txt
   
   # 或者使用 uv (更快)
   uv pip install -r requirements.txt
   ```

4. 开发模式安装：
   ```bash
   pip install -e .
   ```

## 🖥️ Command Line Usage

### Basic Commands

#### Run Detection
```bash
# Basic detection with default config
python -m flowed.cli detect

# Specify custom config file
python -m flowed.cli detect --config path/to/config.yaml

# Enable verbose output
python -m flowed.cli detect -v

# Force model retraining
python -m flowed.cli detect --force-retrain
```

#### Train Models
```bash
# Train new models
python -m flowed.cli train --config config/default.yaml

# Retrain existing models
python -m flowed.cli retrain --config config/production.yaml
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--config FILE` | Path to configuration YAML file (default: custom_config.yaml) |
| `--source PATH` | Override data source path |
| `--destination PATH` | Override output destination path |
| `--log-level LEVEL` | Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `-v, --verbose` | Enable verbose output (same as --log-level DEBUG) |
| `--force-retrain` | Force retraining of models |
| `--debug` | Enable debug mode with additional diagnostics |

### Configuration File

The configuration file (default: `custom_config.yaml`) allows you to customize:
- Data source and output paths
- Feature extraction parameters
- Model hyperparameters
- Logging settings
- Visualization options

Example minimal config:
```yaml
data:
  source: data/raw/
  destination: data/processed/

model:
  detection_mode: collaborative  # Options: isolation_forest, lstm_autoencoder, collaborative
  save_dir: data/models/

logging:
  level: INFO
  file: logs/flowed.log

visualization:
  enable: true
  output_dir: data/reports/
```

## 🛠 项目结构

```
flowed/
├── config/              # 配置文件
├── data/                # 数据文件
│   ├── raw/            # 原始 PCAP 文件
│   ├── processed/      # 处理后的数据
│   ├── models/         # 训练好的模型
│   └── reports/        # 生成的报告
├── docs/               # 文档
├── src/                # 源代码
│   └── flowed/
│       ├── data/       # 数据采集与处理
│       ├── features/   # 特征工程
│       ├── models/     # 异常检测模型
│       └── visualization/  # 可视化组件
├── tests/              # 测试用例
├── .gitignore
├── README.md
├── requirements.txt
└── setup.py
```

## 📝 配置说明

通过 `config/default.yaml` 文件可以配置：
- 输入/输出目录
- 特征提取参数
- 模型超参数
- 日志级别
- 可视化选项

## 📊 可视化展示

### 网络流量图
![Sankey Diagram](docs/images/sankey_diagram.png)

### 协议分布
![Protocol Distribution](docs/images/protocol_rose.png)

## 📈 Changelog

### [0.1.0] - 2025-07-16
#### 已实现功能
- ✅ PCAP 文件解析与处理
- ✅ 多维度特征提取
- ✅ 基于 Isolation Forest 的异常检测
- ✅ 交互式可视化报告生成
- ✅ 配置化运行

#### 技术栈
- Python 3.8+
- Scikit-learn
- Pandas
- Plotly
- PyYAML
- Loguru

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

## 📄 开源协议

本项目采用 [MIT 协议](LICENSE) 开源。
