# Section 5: Phase I Source Code Implementation

This section documents the Phase I Source Code deliverables for the CyberRisk Monitor project, organized according to the Unit 4 evaluation criteria: Project Setup, Core Functionality, Documentation, and Unit Testing.

---

## 5.1 Project Setup

### 5.1.1 Development Environment Configuration

The CyberRisk Monitor project uses Python 3.10+ as the primary development language, selected for its robust standard library, cross-platform compatibility, and team familiarity. Each team member configures their local development environment using the following tools:

| Tool | Purpose | Version |
|------|---------|---------|
| Python | Programming Language | 3.10+ |
| Visual Studio Code / PyCharm | Integrated Development Environment | Latest |
| Git | Version Control | 2.40+ |
| pytest | Testing Framework | 7.0.0+ |
| pip | Package Management | 23.0+ |

### 5.1.2 Library and Package Installation

Dependencies are managed through `requirements.txt` and kept intentionally minimal to reduce setup complexity and ensure cross-platform compatibility. The project distinguishes between core and development dependencies:

**Core Dependencies (Standard Library Only):**
- `json` - Configuration and data serialization
- `csv` - CSV log format parsing
- `re` - Regular expression pattern matching
- `datetime` - Timestamp handling and time window calculations
- `logging` - Application logging and debugging
- `pathlib` - Cross-platform file path handling
- `dataclasses` - Data structure definitions
- `collections` - defaultdict for event aggregation
- `math` - Risk scoring calculations (log2 frequency multiplier)

**Development Dependencies (requirements.txt):**
```
pytest>=7.0.0
pytest-cov>=4.0.0
black>=23.0.0
isort>=5.12.0
mypy>=1.0.0
```

**Optional Dependencies:**
```
streamlit>=1.30.0  # Web dashboard (future phase)
```

Installation is accomplished via:
```bash
pip install -e .           # Install package in development mode
pip install -e ".[dev]"    # Include development dependencies
```

### 5.1.3 Version Control Integration

The project uses Git with a shared GitHub repository (https://github.com/CMSC-495-capstone-spring2026-cyberrisk/CyberRisk) as the central collaboration platform. Version control practices include:

- **Branching Strategy**: Feature branches for isolated development (e.g., `cassandra-backend` for storage features)
- **Commit Standards**: Descriptive commit messages explaining the "why" of changes
- **Pull Request Workflow**: Code review through GitHub before merging to main
- **Issue Tracking**: GitHub Issues for task management and bug tracking
- **Protected Main Branch**: Direct commits to main are discouraged; changes flow through reviewed branches

### 5.1.4 Project Structure and Organization

The repository follows a well-organized structure that separates source code, configuration, test data, and documentation:

```
CyberRisk/
├── src/
│   └── cyberrisk/
│       ├── __init__.py              # Package initialization
│       ├── cli.py                   # Command-line interface
│       ├── core/
│       │   ├── __init__.py
│       │   ├── log_parser.py        # Log ingestion and normalization
│       │   ├── rule_engine.py       # Detection rule evaluation
│       │   └── risk_scorer.py       # Risk scoring algorithm
│       ├── reporting/
│       │   ├── __init__.py
│       │   └── report_generator.py  # Report generation (text/JSON/HTML)
│       └── ui/
│           └── __init__.py          # UI module placeholder
├── config/
│   └── rules.json                   # Detection rules configuration (15 rules)
├── data/
│   └── sample_logs/                 # Test datasets
│       ├── sample_data.csv
│       ├── sample_json.log
│       └── sample_syslog.log
├── tests/
│   ├── __init__.py
│   ├── test_log_parser.py           # LogParser unit tests (16 tests)
│   ├── test_rule_engine.py          # RuleEngine unit tests (14 tests)
│   └── test_risk_scorer.py          # RiskScorer unit tests (45 tests)
├── docs/                            # Project documentation
├── output/                          # Generated reports
├── setup.py                         # Package configuration
├── requirements.txt                 # Dependencies
├── LICENSE                          # MIT License
└── README.md                        # Project documentation
```

This structure ensures clear separation of concerns:
- **src/cyberrisk/core/**: Core business logic modules
- **src/cyberrisk/reporting/**: Output generation components
- **config/**: External configuration files (rules, settings)
- **data/**: Test data isolated from source code
- **tests/**: Test files mirror source structure

---

## 5.2 Core Functionality

### 5.2.1 Implementation of Project Requirements

Phase I implements the foundational features outlined in the project requirements document. The following table maps requirements to implementation status:

| Req ID | Requirement | Implementation | Status |
|--------|-------------|----------------|--------|
| FR-01 | Parse syslog, JSON, CSV formats | `LogParser` class with auto-detection | Complete |
| FR-02 | Apply detection rules to logs | `RuleEngine` with 15 rules from `rules.json` | Complete |
| FR-03 | Identify security patterns | Pattern matching for failed logins, port scans, privilege escalation | Complete |
| FR-04 | Calculate numerical risk scores | `RiskScorer` with frequency/context multipliers | Complete |
| FR-05 | Categorize risks (Low/Medium/High/Critical) | Threshold-based categorization (0-25/26-50/51-75/76+) | Complete |
| FR-06 | Generate summary reports | `ReportGenerator` with text/JSON/HTML output | Complete |
| FR-07 | User interface for interaction | CLI via `cli.py` with `cyberrisk analyze` command | Complete |
| FR-08 | Adjustable detection thresholds | Rules configurable via JSON; runtime threshold modification | Complete |

### 5.2.2 Algorithm Design and Efficiency

**Log Parsing Algorithm:**
The `LogParser` class implements efficient format detection using signature analysis rather than attempting all formats:

```python
def detect_format(self, file_path: Path) -> str:
    """Auto-detect log format by examining file signature."""
    with open(file_path) as f:
        first_line = f.readline()
        if first_line.strip().startswith('{'):
            return "json"
        elif ',' in first_line and any(h in first_line.lower()
             for h in ['timestamp', 'date', 'time']):
            return "csv"
        else:
            return "syslog"
```

Time Complexity: O(1) for format detection, O(n) for parsing where n = number of log entries.

**Rule Evaluation Algorithm:**
The `RuleEngine` uses compiled regular expressions for pattern matching and maintains an event buffer for threshold-based detection within time windows:

```python
# Threshold detection with sliding time window
def _record_match(self, rule: Rule, entry: LogEntry) -> None:
    group_key = rule.get_group_key(entry)
    buffer = self._event_buffer[rule.rule_id][group_key]
    buffer.append((entry.timestamp, entry))

    # Clean entries outside time window - O(n) but n is bounded by threshold
    cutoff = entry.timestamp - timedelta(seconds=rule.time_window)
    buffer[:] = [(ts, e) for ts, e in buffer if ts >= cutoff]

    if len(buffer) >= rule.threshold:
        self._create_detection(rule, buffer, group_key)
```

**Risk Scoring Algorithm:**
The scoring algorithm balances simplicity with meaningful risk differentiation:

```
Final Score = Base Score × Frequency Multiplier × Context Multiplier

Where:
- Base Score = Rule severity (1-10)
- Frequency Multiplier = log2(event_count + 1)  # Diminishing returns
- Context Multiplier = Based on patterns (root: 1.5, admin: 1.4, localhost: 0.7)
```

This logarithmic frequency scaling prevents score inflation while still rewarding detection of repeated events.

### 5.2.3 Modular Code Organization

The codebase follows a modular architecture with clear separation of concerns:

| Module | Responsibility | Dependencies |
|--------|----------------|--------------|
| `log_parser.py` | Data ingestion and normalization | Standard library only |
| `rule_engine.py` | Detection rule evaluation | `log_parser.LogEntry` |
| `risk_scorer.py` | Risk calculation and categorization | `rule_engine.Detection` |
| `report_generator.py` | Output formatting | `risk_scorer.RiskAssessment` |
| `cli.py` | User interaction | All core modules |

**Dependency Flow:**
```
LogParser → RuleEngine → RiskScorer → ReportGenerator → CLI
```

Each module exposes clean interfaces through dataclasses:
- `LogEntry`: Normalized log representation
- `Rule`: Detection rule specification
- `Detection`: Security event finding
- `ScoredEvent`: Risk-scored detection
- `RiskAssessment`: Aggregate risk analysis

This modularity enables:
- Independent testing of each component
- Easy substitution of implementations
- Clear responsibility boundaries
- Minimal code duplication

---

## 5.3 Documentation

### 5.3.1 Code Formatting Standards

The project enforces consistent code formatting through automated tools:

- **Black**: Code formatter with 88-character line length
- **isort**: Import statement organization
- **Type Hints**: All public functions include type annotations

Example of documented function:

```python
def score_detections(self, detections: list[Detection]) -> RiskAssessment:
    """
    Score a list of detections and produce a risk assessment.

    Args:
        detections: List of Detection objects to score

    Returns:
        RiskAssessment containing scored events and overall risk
    """
```

### 5.3.2 Inline Documentation and Comments

All modules include comprehensive docstrings following Google style:

**Module-level docstrings** explain purpose and author:
```python
"""
RiskScorer Module - Calculates risk scores and assigns severity levels.

Implements the risk scoring algorithm that aggregates detection events
into cumulative risk scores and categorizes them into severity levels.

Author: CyberRisk Team
"""
```

**Class docstrings** document attributes and usage:
```python
class RiskScorer:
    """
    Calculates risk scores and severity levels for detections.

    The scoring algorithm considers:
    - Base severity from the triggering rule
    - Frequency of events (more events = higher risk)
    - Contextual factors (certain patterns are higher risk)

    Risk Levels:
    - Low: 0-25 points
    - Medium: 26-50 points
    - High: 51-75 points
    - Critical: 76+ points

    Example:
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)
        print(f"Total Risk: {assessment.risk_level} ({assessment.total_score})")
    """
```

### 5.3.3 README and Project Documentation

The project README (`README.md`) provides comprehensive documentation:

1. **Project Overview**: Description of CyberRisk Monitor and its capabilities
2. **Installation Instructions**: Step-by-step setup for all platforms
3. **Usage Examples**: CLI commands and Python API usage
4. **Supported Log Formats**: syslog, JSON, CSV with examples
5. **Detection Rules**: Table of 15 built-in rules with severity levels
6. **Architecture Overview**: Module descriptions and data flow
7. **Testing Instructions**: How to run the test suite
8. **Team Information**: Contributors and course context

### 5.3.4 Dependencies and Version Documentation

**setup.py** documents package metadata and dependencies:
```python
setup(
    name="cyberrisk-monitor",
    version="0.1.0",
    description="A lightweight rule-based cybersecurity monitoring tool",
    python_requires=">=3.10",
    install_requires=[],  # Core uses standard library only
    extras_require={
        "dev": ["pytest>=7.0.0", "pytest-cov>=4.0.0", "black>=23.0.0"]
    }
)
```

**requirements.txt** specifies exact versions for reproducibility:
```
pytest>=7.0.0
pytest-cov>=4.0.0
black>=23.0.0
isort>=5.12.0
mypy>=1.0.0
```

---

## 5.4 Unit Testing

### 5.4.1 Testing Framework and Approach

The project uses **pytest** as the testing framework, selected for:
- Simple test discovery and execution
- Powerful fixture system for test data management
- Rich assertion introspection
- Extensive plugin ecosystem (coverage, parallel execution)

Tests are organized to mirror the source code structure:
```
tests/
├── test_log_parser.py      # 16 tests for LogParser
├── test_rule_engine.py     # 14 tests for RuleEngine
└── test_risk_scorer.py     # 45 tests for RiskScorer
```

**Total: 75 tests** covering all core modules.

### 5.4.2 Test Coverage by Module

| Module | Test File | Tests | Coverage Areas |
|--------|-----------|-------|----------------|
| `log_parser.py` | `test_log_parser.py` | 16 | Format detection, syslog/JSON/CSV parsing, error handling |
| `rule_engine.py` | `test_rule_engine.py` | 14 | Rule creation, pattern matching, threshold detection, grouping |
| `risk_scorer.py` | `test_risk_scorer.py` | 45 | Scoring algorithm, categorization, context multipliers, summary generation |

### 5.4.3 Test Case Documentation

Tests are organized into logical test classes with descriptive names:

**LogParser Tests (`test_log_parser.py`):**
```python
class TestLogParser:
    def test_detect_format_syslog(self): ...
    def test_detect_format_json(self): ...
    def test_detect_format_csv(self): ...
    def test_parse_syslog_line(self): ...
    def test_parse_json_line(self): ...
    def test_parse_csv_file(self): ...
    def test_handle_malformed_entry(self): ...
```

**RuleEngine Tests (`test_rule_engine.py`):**
```python
class TestRule:
    def test_create_rule(self): ...
    def test_rule_matches(self): ...
    def test_rule_disabled(self): ...

class TestRuleEngine:
    def test_engine_initialization(self): ...
    def test_evaluate_logs_threshold(self): ...
    def test_evaluate_logs_grouping(self): ...
```

**RiskScorer Tests (`test_risk_scorer.py`):**
```python
class TestScoreCategorization:
    def test_categorize_low_score(self): ...      # 0-25 → Low
    def test_categorize_medium_score(self): ...   # 26-50 → Medium
    def test_categorize_high_score(self): ...     # 51-75 → High
    def test_categorize_critical_score(self): ... # 76+ → Critical

class TestContextMultiplier:
    def test_root_user_increases_score(self): ...
    def test_localhost_decreases_score(self): ...

class TestSummaryGeneration:
    def test_summary_by_category(self): ...
    def test_summary_by_rule(self): ...
    def test_summary_timeline(self): ...
```

### 5.4.4 Running Tests

Tests can be executed using the following commands:

```bash
# Run all tests
pytest tests/ -v

# Run tests with coverage report
pytest tests/ --cov=src/cyberrisk --cov-report=html

# Run specific test file
pytest tests/test_risk_scorer.py -v

# Run tests matching a pattern
pytest tests/ -k "test_categorize" -v
```

**Current Test Results:**
```
======================== 75 passed in 0.09s ========================
```

### 5.4.5 Test Fixtures and Data Management

Tests use pytest fixtures to provide reusable test data:

```python
@pytest.fixture
def sample_log_entry():
    """Create a sample LogEntry for testing."""
    return LogEntry(
        timestamp=datetime(2026, 1, 28, 10, 30, 0),
        source_ip="192.168.1.100",
        message="Failed password for admin from 192.168.1.100",
        event_type="authentication_failure",
        user="admin",
    )

@pytest.fixture
def sample_detection(sample_log_entry):
    """Create a sample Detection for testing."""
    return Detection(
        detection_id="DET-000001",
        rule_id="RULE-001",
        rule_name="Brute Force Login",
        log_entries=[sample_log_entry],
        timestamp=datetime(2026, 1, 28, 10, 30, 0),
        severity=8,
    )
```

This fixture-based approach ensures:
- Consistent test data across test cases
- Reduced code duplication
- Easy modification of test scenarios
- Clear documentation of expected data formats

---

## 5.5 Phase I Summary

Phase I of the CyberRisk Monitor project successfully delivers:

| Deliverable | Status | Evidence |
|-------------|--------|----------|
| Functional development environment | Complete | Cross-platform setup verified |
| Version control integration | Complete | GitHub repository with history |
| Core modules implemented | Complete | LogParser, RuleEngine, RiskScorer, ReportGenerator |
| 15 detection rules | Complete | `config/rules.json` |
| CLI interface | Complete | `cyberrisk analyze` command |
| Comprehensive unit tests | Complete | 75 tests, all passing |
| Code documentation | Complete | Docstrings, README, type hints |

The Phase I implementation establishes a stable foundation for continued development in subsequent phases, with clean architecture, thorough testing, and comprehensive documentation supporting maintainability and extensibility.
