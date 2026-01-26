"""
CyberRisk Monitor - A Lightweight Rule-Based Cybersecurity Monitoring Tool

This package provides functionality for analyzing security logs, detecting
suspicious patterns using predefined rules, and assessing risk levels.
"""

__version__ = "0.1.0"
__author__ = "CyberRisk Team"

from cyberrisk.core.log_parser import LogParser, LogEntry
from cyberrisk.core.rule_engine import RuleEngine, Rule, Detection
from cyberrisk.core.risk_scorer import RiskScorer

__all__ = [
    "LogParser",
    "LogEntry",
    "RuleEngine",
    "Rule",
    "Detection",
    "RiskScorer",
]
