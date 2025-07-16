# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
