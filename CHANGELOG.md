# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-07-16

### Added
- **交互式可视化看板**: 新增了基于 Plotly 的交互式网络流量分析看板
- **协议分析功能**: 添加了对多种网络协议的自动识别与统计分析
- **主机行为分析**: 实现了基于时间窗口的主机行为特征计算
- **中文文档**: 添加了完整的中文使用文档和 API 文档
- **配置系统**: 实现了基于 YAML 的灵活配置系统
- **日志系统**: 集成了 Loguru 日志框架，提供详细的运行日志

### Changed
- **重构特征提取管道**: 优化了特征提取流程，提高了处理效率
- **改进异常检测模型**: 优化了 Isolation Forest 模型的参数和特征选择
- **增强可视化效果**: 改进了 Sankey 图和玫瑰图的可视化效果
- **更新项目结构**: 优化了项目目录结构，提高了代码可维护性

### Fixed
- 修复了协议分布图表重复显示的问题
- 修复了特征提取过程中的空值处理
- 解决了模型加载时的依赖问题
- 修复了报告生成中的样式问题

## [0.2.0] - 2025-07-15

### Added
- **Automated Anomaly Interpretation**: Added a new feature to the HTML report that provides a textual explanation of why detected anomalies are considered unusual, based on their statistical properties.
- **CHANGELOG.md**: This file was created to track project milestones and versions.
- **DESIGN_AND_ARCHITECTURE.md**: Added a new section to track current status and known issues.

### Fixed
- **Critical Model Training Crash (Exit Code 130 & TypeError)**: Resolved persistent and silent runtime crashes during the model training phase. The root causes were identified as non-numeric `Timestamp` objects and the presence of `NaN`/`inf` values in the feature set. The fix involved implementing a robust data cleaning and pre-processing step in the `IsolationForestModel` to ensure only clean, numeric data is passed to the `scikit-learn` backend.

### Changed
- **Updated Design Documentation**: Significantly updated `DESIGN_AND_ARCHITECTURE.md` to reflect the latest debugging efforts, architectural improvements, and added features.

## [0.1.0] - Initial Version

- Initial project refactoring to a modular architecture.
- Implemented core components: data ingestor, feature extractor, model manager, and basic CLI.
