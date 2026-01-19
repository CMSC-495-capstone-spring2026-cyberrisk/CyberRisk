# 🛡️ CyberRisk Monitor

**A lightweight, rule-based cybersecurity monitoring and risk assessment tool**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![UMGC CMSC 495](https://img.shields.io/badge/UMGC-CMSC%20495-red.svg)](https://www.umgc.edu/)

---

## 📋 Overview

CyberRisk Monitor is a proof-of-concept security tool designed to analyze security logs using configurable detection rules to identify potential threats and suspicious activity. Built for educational purposes and small teams seeking an accessible introduction to cybersecurity monitoring.

### What it does:
- 📄 **Parse** security logs in multiple formats (syslog, JSON, CSV)
- 🔍 **Detect** common attack patterns using rule-based analysis
- ⚠️ **Assess** risk levels and categorize threats (Low/Medium/High/Critical)
- 📊 **Visualize** findings through an intuitive dashboard

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Multi-format Log Parser** | Supports syslog, JSON, and CSV log formats |
| **Rule Engine** | Configurable detection rules for threat identification |
| **Risk Scoring** | Algorithmic risk assessment with severity categorization |
| **Dashboard** | Visual summary of security findings and alerts |
| **Report Generation** | Export findings for documentation and review |

### Detection Capabilities
- 🔐 Brute force login attempts
- 🌐 Port scanning activity
- ⬆️ Privilege escalation attempts
- 🚨 Anomalous access patterns
- 📍 Suspicious IP activity

---

## 🛠️ Tech Stack

- **Language:** Python 3.10+
- **Dashboard:** Streamlit / Flask (TBD)
- **Testing:** pytest
- **Data Formats:** JSON, YAML, CSV
- **Version Control:** Git

---

## 📁 Project Structure

```
cyberrisk-monitor/
├── src/
│   ├── parser/          # Log parsing modules
│   ├── rules/           # Detection rule engine
│   ├── risk/            # Risk assessment calculator
│   └── dashboard/       # UI and reporting
├── config/
│   └── rules.yaml       # Detection rule configurations
├── data/
│   └── samples/         # Sample log files for testing
├── tests/               # Unit and integration tests
├── docs/                # Documentation
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/CMSC-495-capstone-spring2026-cyberrisk/cyberrisk-monitor.git
cd cyberrisk-monitor

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Quick Start

```bash
# Run with sample data
python -m src.main --input data/samples/sample_logs.json

# Launch dashboard
python -m src.dashboard
```

---

## 📖 Usage

### Command Line
```bash
# Analyze a log file
python -m src.main --input <logfile> --format [syslog|json|csv]

# Specify custom rules
python -m src.main --input <logfile> --rules config/custom_rules.yaml

# Generate report
python -m src.main --input <logfile> --output report.html
```

### Configuration
Detection rules can be customized in `config/rules.yaml`:
```yaml
rules:
  brute_force:
    threshold: 50
    timeframe_minutes: 5
    severity: HIGH
  port_scan:
    port_threshold: 20
    severity: MEDIUM
```

---

## 👥 Team

| Name | Role | GitHub |
|------|------|--------|
| [Member 1] | Project Manager | [@username](https://github.com/username) |
| [Member 2] | Lead Developer | [@username](https://github.com/username) |
| [Member 3] | Backend Developer | [@username](https://github.com/username) |
| [Member 4] | Frontend/QA | [@username](https://github.com/username) |

---

## 💬 Communication

- **Discord:** [Join our server](https://discord.gg/NVQJByxh)
- **Repository:** [GitHub](https://github.com/CMSC-495-capstone-spring2026-cyberrisk)

---

## 📅 Project Timeline

| Phase | Dates | Status |
|-------|-------|--------|
| Planning & Design | Jan 21 - Jan 27 | 🔄 In Progress |
| Core Development | Jan 28 - Feb 10 | ⏳ Upcoming |
| Integration & Dashboard | Feb 11 - Feb 17 | ⏳ Upcoming |
| Testing & Refinement | Feb 18 - Feb 24 | ⏳ Upcoming |
| Final Delivery | Feb 25 - Mar 3 | ⏳ Upcoming |

---

## 🤝 Contributing

This is an academic project for UMGC CMSC 495 (Spring 2026). Contributions are limited to team members during the course period.

### Development Workflow
1. Create a feature branch from `main`
2. Make your changes
3. Write/update tests
4. Submit a merge request for code review
5. Merge after approval

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🎓 Acknowledgments

- UMGC CMSC 495 - Computer Science Capstone
- Spring 2026

---

<p align="center">
  <i>Built with ☕ by the CyberRisk Monitor Team</i>
</p>
