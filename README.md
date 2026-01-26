# CyberRisk Monitor

**A lightweight, rule-based cybersecurity monitoring and risk assessment tool**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-30%20passed-brightgreen.svg)](tests/)
[![UMGC CMSC 495](https://img.shields.io/badge/UMGC-CMSC%20495-red.svg)](https://www.umgc.edu/)

---

## Overview

CyberRisk Monitor is a proof-of-concept security tool designed to analyze security logs using configurable detection rules to identify potential threats and suspicious activity. Built as a capstone project for UMGC CMSC 495, it provides an accessible introduction to cybersecurity monitoring for educational purposes and small teams.

### Key Capabilities

- **Parse** security logs in multiple formats (syslog, JSON, CSV)
- **Detect** common attack patterns using 15 predefined rules
- **Assess** risk levels with algorithmic scoring (Low/Medium/High/Critical)
- **Report** findings in text, JSON, or styled HTML dashboards

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-format Log Parser** | Auto-detects and parses syslog, JSON, and CSV formats |
| **Rule Engine** | Threshold-based detection with time windows and IP/user grouping |
| **Risk Scoring** | Multi-factor scoring with context-aware adjustments |
| **Report Generation** | Text summaries, JSON exports, and styled HTML reports |
| **CLI Interface** | Easy-to-use command-line tool for analysis |

### Detection Rules (15 Built-in)

| Rule | Severity | Description |
|------|----------|-------------|
| Brute Force Login | 8/10 | 5+ failed logins from same IP in 5 minutes |
| Port Scan Detection | 7/10 | 10+ connection attempts to different ports |
| Privilege Escalation | 9/10 | sudo/root access attempts |
| SSH Auth Failure | 6/10 | Failed SSH authentication attempts |
| Suspicious File Access | 8/10 | Access to /etc/shadow, /etc/passwd, etc. |
| Malware Signatures | 10/10 | Known malware pattern detection |
| New Admin Account | 9/10 | Creation of accounts with admin privileges |
| Service Stopped | 7/10 | Critical services terminated unexpectedly |
| Large Data Transfer | 6/10 | Unusual outbound data transfers |
| Firewall Modification | 7/10 | Changes to firewall rules |
| *...and 5 more* | | |

---

## Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/CMSC-495-capstone-spring2026-cyberrisk/CyberRisk.git
cd CyberRisk

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .

# Verify installation
cyberrisk --version
```

### Development Install

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

---

## Usage

### Command Line Interface

```bash
# Analyze a log file
cyberrisk analyze path/to/logfile.log

# Export HTML report
cyberrisk analyze security.log -o report.html -f html

# Export JSON data
cyberrisk analyze security.log -o results.json -f json

# Use custom detection rules
cyberrisk analyze security.log --rules my_rules.json

# List all available rules
cyberrisk list-rules

# Verbose output for debugging
cyberrisk analyze security.log -v
```

### Python API

```python
from cyberrisk.core.log_parser import LogParser
from cyberrisk.core.rule_engine import RuleEngine
from cyberrisk.core.risk_scorer import RiskScorer
from cyberrisk.reporting.report_generator import ReportGenerator

# 1. Parse your log file (format auto-detected)
parser = LogParser()
entries = parser.parse_file("security.log")
print(f"Parsed {len(entries)} log entries")

# 2. Load rules and detect threats
engine = RuleEngine()
engine.load_rules("config/rules.json")
detections = engine.evaluate_logs(entries)
print(f"Found {len(detections)} security detections")

# 3. Calculate risk scores
scorer = RiskScorer()
assessment = scorer.score_detections(detections)
print(f"Risk Level: {assessment.risk_category} (Score: {assessment.total_score})")

# 4. Generate reports
generator = ReportGenerator()
print(generator.generate_summary(assessment))  # Console output
generator.export_report("report.html", assessment, format="html")  # HTML file
```

### Supported Log Formats

| Format | Extensions | Example |
|--------|------------|---------|
| **Syslog** | `.log`, `.txt` | `Jan 26 08:15:22 server sshd[1234]: Failed password for admin` |
| **JSON** | `.json` | `{"timestamp": "2026-01-26T10:00:00Z", "message": "Failed login"}` |
| **CSV** | `.csv` | Headers: `timestamp,source_ip,user,message,event_type` |

### Understanding Risk Levels

| Level | Score | Action Required |
|-------|-------|-----------------|
| **Low** | 0-25 | Routine monitoring, no immediate action |
| **Medium** | 26-50 | Review findings, investigate if pattern continues |
| **High** | 51-75 | Prompt investigation recommended |
| **Critical** | 76+ | Immediate action required, escalate to security team |

---

## Project Structure

```
CyberRisk/
├── src/cyberrisk/
│   ├── core/
│   │   ├── log_parser.py      # Multi-format log parsing
│   │   ├── rule_engine.py     # Detection rule evaluation
│   │   └── risk_scorer.py     # Risk calculation & categorization
│   ├── reporting/
│   │   └── report_generator.py # Text, JSON, HTML reports
│   ├── ui/                    # Future: Web dashboard
│   └── cli.py                 # Command-line interface
├── config/
│   └── rules.json             # 15 predefined detection rules
├── data/
│   └── sample_logs/           # Sample data for testing
├── tests/                     # Unit tests (30 tests, 100% passing)
├── docs/                      # Project documentation
├── requirements.txt
├── setup.py
└── README.md
```

---

## Configuration

### Custom Detection Rules

Create a JSON file with your rules:

```json
{
  "rules": [
    {
      "rule_id": "CUSTOM-001",
      "name": "My Custom Rule",
      "description": "Detects specific pattern",
      "pattern": "error.*critical",
      "field": "message",
      "threshold": 3,
      "time_window": 300,
      "severity": 7,
      "enabled": true,
      "group_by": "source_ip"
    }
  ]
}
```

Then use it:
```bash
cyberrisk analyze logs.log --rules my_rules.json
```

---

## Team

| Name | Role | Responsibilities |
|------|------|------------------|
| **Mustafa Black-Castle** | Project Lead | Project coordination, RuleEngine development, final demo |
| **Daniel S. Garrett** | Lead Developer | LogParser module, testing lead, performance validation |
| **Nicholas Porpora** | Developer | RiskScorer module, system integration |
| **Cassandra Santacruz** | Developer | UserInterface, ReportGenerator, documentation |

---

## Project Timeline

| Phase | Week | Status |
|-------|------|--------|
| Planning & Design | Week 3 (Jan 21-27) | Completed |
| Core Development I (Parser) | Week 4 (Jan 28 - Feb 3) | Completed |
| Core Development II (Engine) | Week 5 (Feb 4-10) | In Progress |
| Integration | Week 6 (Feb 11-17) | Upcoming |
| UI & Testing | Week 7 (Feb 18-24) | Upcoming |
| Final Delivery | Week 8 (Feb 25 - Mar 3) | Upcoming |

---

## Testing

Run the test suite:

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=src/cyberrisk --cov-report=html

# Run specific test file
pytest tests/test_log_parser.py -v
```

Current status: **30 tests passing**

---

## Communication

- **Discord:** [Join our server](https://discord.gg/NVQJByxh)
- **Repository:** [GitHub](https://github.com/CMSC-495-capstone-spring2026-cyberrisk/CyberRisk)

---

## Contributing

This is an academic project for UMGC CMSC 495 (Spring 2026). Contributions are limited to team members during the course period.

### Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Write/update tests
4. Run `pytest` to ensure all tests pass
5. Submit a pull request for code review
6. Merge after approval

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- UMGC CMSC 495 - Computer Science Capstone
- Spring 2026

---

<p align="center">
  <i>Built by the CyberRisk Monitor Team</i><br>
  <i>University of Maryland Global Campus</i>
</p>
