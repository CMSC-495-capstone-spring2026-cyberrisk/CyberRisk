"""
Unit tests for the RuleEngine module.
"""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cyberrisk.core.log_parser import LogEntry
from cyberrisk.core.rule_engine import Rule, RuleEngine, Detection


class TestRule:
    """Tests for Rule dataclass."""

    def test_create_rule(self):
        """Test creating a Rule with required fields."""
        rule = Rule(
            rule_id="TEST-001",
            name="Test Rule",
            pattern="failed.*login",
            severity=5,
        )
        assert rule.rule_id == "TEST-001"
        assert rule.enabled is True
        assert rule.threshold == 1

    def test_rule_matches(self):
        """Test rule pattern matching."""
        rule = Rule(
            rule_id="TEST-001",
            name="Failed Login",
            pattern="failed.*password",
            match_field="message",
        )

        entry_match = LogEntry(
            timestamp=datetime.now(),
            message="Failed password for user admin",
        )
        entry_no_match = LogEntry(
            timestamp=datetime.now(),
            message="Successful login",
        )

        assert rule.matches(entry_match) is True
        assert rule.matches(entry_no_match) is False

    def test_rule_disabled(self):
        """Test that disabled rules don't match."""
        rule = Rule(
            rule_id="TEST-001",
            name="Test Rule",
            pattern="test",
            enabled=False,
        )

        entry = LogEntry(timestamp=datetime.now(), message="test message")
        assert rule.matches(entry) is False

    def test_rule_to_dict(self):
        """Test converting Rule to dictionary."""
        rule = Rule(
            rule_id="TEST-001",
            name="Test Rule",
            description="A test rule",
            pattern="test",
            severity=7,
            tags=["test", "example"],
        )
        data = rule.to_dict()

        assert data["rule_id"] == "TEST-001"
        assert data["severity"] == 7
        assert "test" in data["tags"]

    def test_rule_from_dict(self):
        """Test creating Rule from dictionary."""
        data = {
            "rule_id": "TEST-001",
            "name": "Test Rule",
            "pattern": "test",
            "severity": 8,
            "threshold": 3,
        }
        rule = Rule.from_dict(data)

        assert rule.rule_id == "TEST-001"
        assert rule.severity == 8
        assert rule.threshold == 3


class TestRuleEngine:
    """Tests for RuleEngine class."""

    def test_engine_initialization(self):
        """Test RuleEngine initialization."""
        engine = RuleEngine()
        assert len(engine.rules) == 0
        assert len(engine.detections) == 0

    def test_add_rule(self):
        """Test adding rules to engine."""
        engine = RuleEngine()
        rule = Rule(rule_id="TEST-001", name="Test Rule", pattern="test")

        engine.add_rule(rule)
        assert len(engine.rules) == 1
        assert "TEST-001" in engine.rules

    def test_remove_rule(self):
        """Test removing rules from engine."""
        engine = RuleEngine()
        rule = Rule(rule_id="TEST-001", name="Test Rule", pattern="test")

        engine.add_rule(rule)
        assert engine.remove_rule("TEST-001") is True
        assert len(engine.rules) == 0
        assert engine.remove_rule("NONEXISTENT") is False

    def test_load_rules_from_file(self):
        """Test loading rules from JSON file."""
        rules_data = {
            "rules": [
                {"rule_id": "R1", "name": "Rule 1", "pattern": "test1", "severity": 5},
                {"rule_id": "R2", "name": "Rule 2", "pattern": "test2", "severity": 7},
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(rules_data, f)
            f.flush()

            engine = RuleEngine()
            count = engine.load_rules(f.name)

            assert count == 2
            assert len(engine.rules) == 2

    def test_evaluate_logs_single_match(self):
        """Test evaluating logs with a single matching entry."""
        engine = RuleEngine()
        rule = Rule(
            rule_id="TEST-001",
            name="Test Detection",
            pattern="failed",
            threshold=1,
            severity=5,
        )
        engine.add_rule(rule)

        entries = [
            LogEntry(timestamp=datetime.now(), message="Failed login attempt"),
        ]

        detections = engine.evaluate_logs(entries)
        assert len(detections) == 1
        assert detections[0].rule_id == "TEST-001"

    def test_evaluate_logs_threshold(self):
        """Test that detections respect threshold settings."""
        engine = RuleEngine()
        rule = Rule(
            rule_id="TEST-001",
            name="Brute Force",
            pattern="failed",
            threshold=3,  # Require 3 events
            time_window=300,
            severity=8,
        )
        engine.add_rule(rule)

        now = datetime.now()
        entries = [
            LogEntry(timestamp=now, message="Failed login 1"),
            LogEntry(timestamp=now + timedelta(seconds=1), message="Failed login 2"),
        ]

        # Only 2 events, threshold is 3
        detections = engine.evaluate_logs(entries)
        assert len(detections) == 0

        # Add third event
        entries.append(
            LogEntry(timestamp=now + timedelta(seconds=2), message="Failed login 3")
        )
        detections = engine.evaluate_logs(entries)
        assert len(detections) == 1

    def test_evaluate_logs_grouping(self):
        """Test that events are grouped correctly."""
        engine = RuleEngine()
        rule = Rule(
            rule_id="TEST-001",
            name="IP Grouped",
            pattern="failed",
            threshold=2,
            group_by="source_ip",
            severity=5,
        )
        engine.add_rule(rule)

        now = datetime.now()
        entries = [
            LogEntry(timestamp=now, source_ip="192.168.1.1", message="Failed 1"),
            LogEntry(timestamp=now, source_ip="192.168.1.2", message="Failed 2"),
            LogEntry(timestamp=now, source_ip="192.168.1.1", message="Failed 3"),  # Same IP
        ]

        detections = engine.evaluate_logs(entries)
        # Only IP .1 should trigger (2 events)
        assert len(detections) == 1
        assert detections[0].group_key == "192.168.1.1"

    def test_get_detection_summary(self):
        """Test detection summary generation."""
        engine = RuleEngine()
        engine.add_rule(Rule(rule_id="R1", name="Rule 1", pattern="test", severity=9))
        engine.add_rule(Rule(rule_id="R2", name="Rule 2", pattern="other", severity=3))

        entries = [
            LogEntry(timestamp=datetime.now(), message="test message"),
            LogEntry(timestamp=datetime.now(), message="other message"),
        ]

        engine.evaluate_logs(entries)
        summary = engine.get_detection_summary()

        assert summary["total"] == 2
        assert "R1" in summary["by_rule"]
        assert "R2" in summary["by_rule"]


class TestDetection:
    """Tests for Detection dataclass."""

    def test_detection_to_dict(self):
        """Test converting Detection to dictionary."""
        entry = LogEntry(timestamp=datetime.now(), message="Test")
        detection = Detection(
            detection_id="DET-001",
            rule_id="RULE-001",
            rule_name="Test Rule",
            log_entries=[entry],
            timestamp=datetime.now(),
            score=50,
            severity=7,
            severity_label="High",
            message="Test detection",
        )

        data = detection.to_dict()
        assert data["detection_id"] == "DET-001"
        assert data["score"] == 50
        assert data["entry_count"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
