"""
CyberRisk Monitor - Setup configuration
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cyberrisk-monitor",
    version="0.1.0",
    author="CyberRisk Team",
    author_email="cyberrisk@example.com",
    description="A lightweight rule-based cybersecurity monitoring and risk assessment tool, that a group of total cool folks are building for their CMSC 495 capstone project.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CMSC-495-capstone-spring2026-cyberrisk/CyberRisk",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Logging",
    ],
    python_requires=">=3.10",
    install_requires=[
        # Core dependencies (none - uses standard library)
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
        ],
        "web": [
            "streamlit>=1.30.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cyberrisk=cyberrisk.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "cyberrisk": ["../config/*.json"],
    },
)
