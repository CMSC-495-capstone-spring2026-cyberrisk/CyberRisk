# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CyberRisk Monitor is a Python-based security log analysis tool that detects threats through pattern matching and rule-based detection. It processes syslog, JSON, and CSV log formats and generates risk assessments.

## Common Commands

```bash
# Install for development
pip install -e ".[dev]"

# Run the CLI
cyberrisk analyze <logfile> --rules config/rules.json --format text|json|html
cyberrisk list-rules --rules config/rules.json

# Run all tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=src/cyberrisk --cov-report=html

# Run a single test file
pytest tests/test_log_parser.py -v

# Code formatting and linting
black src/ tests/
isort src/ tests/
mypy src/
```

## Architecture

The application follows a pipeline architecture with four main stages:

```
CLI (cli.py) → LogParser → RuleEngine → RiskScorer → ReportGenerator
```

### Core Components (`src/cyberrisk/core/`)

- **LogParser** (`log_parser.py`): Auto-detects format (syslog/JSON/CSV) and normalizes logs into `LogEntry` dataclass objects
- **RuleEngine** (`rule_engine.py`): Loads rules from JSON, matches regex patterns against logs, applies threshold-based detection with time windows, generates `Detection` objects
- **RiskScorer** (`risk_scorer.py`): Calculates risk scores using: `base_severity × frequency_multiplier × context_multiplier`. Categories: Low (≤25), Medium (≤50), High (≤75), Critical (>75)

### Other Components

- **ReportGenerator** (`src/cyberrisk/reporting/report_generator.py`): Produces text, JSON, or HTML reports
- **CLI** (`src/cyberrisk/cli.py`): Entry point, handles argument parsing and orchestrates the pipeline

### Key Data Structures

All defined as dataclasses with type hints:
- `LogEntry`: Normalized log with timestamp, IPs, user, message, event_type, severity, metadata
- `Rule`: Detection rule with pattern (regex), threshold, time_window, severity (1-10), group_by
- `Detection`: Triggered event with matched entries and severity label
- `RiskAssessment`: Final analysis with total score, risk category, and statistics

### Configuration

Detection rules live in `config/rules.json`. Each rule has:
- `pattern`: Regex pattern for matching
- `threshold`: Number of matches required within time_window
- `time_window`: Seconds (default 300)
- `severity`: 1-10 scale
- `group_by`: Optional field for per-entity counting (e.g., source_ip)

## CLI Exit Codes

- 0: Success (Low risk)
- 1: Warnings (High risk)
- 2: Errors (Critical risk)

## Testing

Tests are in `tests/` with sample data in `data/sample_logs/`. The test suite covers log parsing across all formats, rule matching, and detection engine logic.
