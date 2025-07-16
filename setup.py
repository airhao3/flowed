from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="flowed",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Network Traffic Anomaly Detection System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/flowed",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "numpy>=1.21.0",
        "pandas>=1.3.0",
        "scikit-learn>=1.0.0",
        "pyshark>=0.4.3",
        "pyyaml>=5.4.1",
        "geoip2",
        "loguru>=0.5.3",
        "requests>=2.26.0",
        "plotly>=5.5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.2.5",
            "pytest-cov>=2.12.1",
            "black>=21.7b0",
            "isort>=5.9.3",
            "mypy>=0.910",
            "flake8>=3.9.2",
        ],
        "docs": [
            "sphinx>=4.1.2",
            "sphinx-rtd-theme>=0.5.2",
            "sphinx-autodoc-typehints>=1.12.0",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    entry_points={
        "console_scripts": [
            "flowed=flowed.cli:main",
        ],
    },
)
