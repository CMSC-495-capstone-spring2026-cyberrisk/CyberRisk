"""
RuleEngine Module - Applies detection rules to log entries.

Provides rule-based detection of security patterns in normalized log data.
Supports configurable rules loaded from JSON/YAML configuration files.

Author: CyberRisk Team
"""

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Callable

from cyberrisk.core.log_parser import LogEntry

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """
    Represents a detection rule for identifying security patterns.

    Rules define conditions that, when matched against log entries,
    generate Detection events for further risk assessment.

    Attributes:
        rule_id: Unique identifier for the rule
        name: Human-readable name
        description: Detailed explanation of what the rule detects
        pattern: Regex pattern or string to match
        field: LogEntry field to match against (e.g., 'message', 'event_type')
        threshold: Number of occurrences needed to trigger (default: 1)
        time_window: Seconds over which threshold is evaluated (default: 300)
        severity: Impact level 1-10 (10 being most severe)
        enabled: Whether the rule is active
        tags: Categories/labels for the rule
        group_by: Field to group events by for threshold counting
    """
    rule_id: str
    name: str
    description: str = ""
    pattern: str = ""
    match_field: str = "message"
    threshold: int = 1
    time_window: int = 300  # 5 minutes default
    severity: int = 5
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    group_by: Optional[str] = None  # e.g., "source_ip" to count per IP

    _compiled_pattern: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        """Compile regex pattern after initialization."""
        if self.pattern:
            try:
                self._compiled_pattern = re.compile(self.pattern, re.IGNORECASE)
            except re.error as e:
                logger.warning(f"Invalid regex pattern for rule {self.rule_id}: {e}")
                self._compiled_pattern = None

    def matches(self, entry: LogEntry) -> bool:
        """
        Check if a log entry matches this rule's pattern.

        Args:
            entry: LogEntry to evaluate

        Returns:
            True if the entry matches the rule pattern
        """
        if not self.enabled:
            return False

        # Get the field value to match against
        field_value = self._get_field_value(entry)
        if field_value is None:
            return False

        # Match against pattern
        if self._compiled_pattern:
            return bool(self._compiled_pattern.search(str(field_value)))
        elif self.pattern:
            return self.pattern.lower() in str(field_value).lower()

        return False

    def _get_field_value(self, entry: LogEntry, field_name: Optional[str] = None) -> Optional[str]:
        """Get the value of a field from a LogEntry."""
        field_name = field_name or self.match_field

        if hasattr(entry, field_name):
            value = getattr(entry, field_name)
            return str(value) if value is not None else None
        elif field_name in entry.metadata:
            return str(entry.metadata[field_name])

        return None

    def get_group_key(self, entry: LogEntry) -> str:
        """Get the grouping key for threshold counting."""
        if self.group_by:
            value = self._get_field_value(entry, self.group_by)
            return value or "unknown"
        return "global"

    def get_severity(self) -> int:
        """Return the severity level."""
        return self.severity

    def enable(self) -> None:
        """Activate the rule."""
        self.enabled = True

    def disable(self) -> None:
        """Deactivate the rule."""
        self.enabled = False

    def to_dict(self) -> dict:
        """Convert rule to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "field": self.match_field,
            "threshold": self.threshold,
            "time_window": self.time_window,
            "severity": self.severity,
            "enabled": self.enabled,
            "tags": self.tags,
            "group_by": self.group_by,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        """Create Rule from dictionary."""
        return cls(
            rule_id=data.get("rule_id", "unknown"),
            name=data.get("name", "Unnamed Rule"),
            description=data.get("description", ""),
            pattern=data.get("pattern", ""),
            match_field=data.get("field", "message"),
            threshold=data.get("threshold", 1),
            time_window=data.get("time_window", 300),
            severity=data.get("severity", 5),
            enabled=data.get("enabled", True),
            tags=data.get("tags", []),
            group_by=data.get("group_by"),
        )


@dataclass
class Detection:
    """
    Represents a detected security event.

    Created when log entries match a rule's conditions and thresholds.

    Attributes:
        detection_id: Unique identifier for this detection
        rule_id: ID of the rule that triggered detection
        rule_name: Name of the triggering rule
        log_entries: List of LogEntry objects that triggered detection
        timestamp: When the detection was generated
        score: Calculated risk score
        severity: Severity level (from rule)
        severity_label: Human-readable severity category
        group_key: The grouping key (e.g., source IP)
        message: Summary message describing the detection
    """
    detection_id: str
    rule_id: str
    rule_name: str
    log_entries: list[LogEntry]
    timestamp: datetime
    score: int = 0
    severity: int = 5
    severity_label: str = "Medium"
    group_key: str = ""
    message: str = ""

    def to_dict(self) -> dict:
        """Convert detection to dictionary representation."""
        return {
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "timestamp": self.timestamp.isoformat(),
            "score": self.score,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "group_key": self.group_key,
            "message": self.message,
            "entry_count": len(self.log_entries),
            "entries": [e.to_dict() for e in self.log_entries[:10]],  # Limit to first 10
        }

    def get_severity(self) -> str:
        """Return severity category label."""
        return self.severity_label

    def get_score(self) -> int:
        """Return calculated risk score."""
        return self.score

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"[{self.severity_label}] {self.rule_name}: {self.message}"


class RuleEngine:
    """
    Applies detection rules to log entries and generates detections.

    The RuleEngine evaluates log entries against a set of configurable rules,
    tracking event counts per rule and group to support threshold-based detection.

    Example:
        engine = RuleEngine()
        engine.load_rules("config/rules.json")
        detections = engine.evaluate_logs(log_entries)
        for detection in detections:
            print(detection.rule_name, detection.severity_label)
    """

    def __init__(self):
        """Initialize the RuleEngine."""
        self.rules: dict[str, Rule] = {}
        self.detections: list[Detection] = []
        self._detection_counter = 0

        # Track events for threshold detection: rule_id -> group_key -> [(timestamp, entry)]
        self._event_buffer: dict[str, dict[str, list[tuple[datetime, LogEntry]]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def load_rules(self, config_path: str | Path) -> int:
        """
        Load rules from a JSON configuration file.

        Args:
            config_path: Path to the rules configuration file

        Returns:
            Number of rules loaded

        Raises:
            FileNotFoundError: If the config file doesn't exist
            ValueError: If the config file is invalid
        """
        config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Rules config not found: {config_path}")

        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Support both {"rules": [...]} and direct array format
        rules_data = data.get("rules", data) if isinstance(data, dict) else data

        if not isinstance(rules_data, list):
            raise ValueError("Rules config must contain a list of rules")

        loaded_count = 0
        for rule_data in rules_data:
            try:
                rule = Rule.from_dict(rule_data)
                self.add_rule(rule)
                loaded_count += 1
            except Exception as e:
                logger.warning(f"Failed to load rule: {e}")

        logger.info(f"Loaded {loaded_count} rules from {config_path}")
        return loaded_count

    def add_rule(self, rule: Rule) -> None:
        """
        Add a rule to the engine.

        Args:
            rule: Rule object to add
        """
        self.rules[rule.rule_id] = rule
        logger.debug(f"Added rule: {rule.rule_id} - {rule.name}")

    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a rule from the engine.

        Args:
            rule_id: ID of the rule to remove

        Returns:
            True if rule was removed, False if not found
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get a rule by ID."""
        return self.rules.get(rule_id)

    def get_rules(self) -> list[Rule]:
        """Get all rules."""
        return list(self.rules.values())

    def get_enabled_rules(self) -> list[Rule]:
        """Get all enabled rules."""
        return [r for r in self.rules.values() if r.enabled]

    def evaluate_logs(self, entries: list[LogEntry]) -> list[Detection]:
        """
        Evaluate log entries against all enabled rules.

        Processes each entry, updates event buffers, and generates
        detections when thresholds are met.

        Args:
            entries: List of LogEntry objects to evaluate

        Returns:
            List of Detection objects generated
        """
        self.detections = []
        self._event_buffer.clear()

        # Sort entries by timestamp for proper threshold evaluation
        sorted_entries = sorted(entries, key=lambda e: e.timestamp)

        for entry in sorted_entries:
            self._evaluate_entry(entry)

        logger.info(f"Generated {len(self.detections)} detections from {len(entries)} entries")
        return self.detections

    def _evaluate_entry(self, entry: LogEntry) -> None:
        """Evaluate a single log entry against all enabled rules."""
        for rule in self.get_enabled_rules():
            if rule.matches(entry):
                self._record_match(rule, entry)

    def _record_match(self, rule: Rule, entry: LogEntry) -> None:
        """Record a rule match and check if threshold is met."""
        group_key = rule.get_group_key(entry)
        buffer = self._event_buffer[rule.rule_id][group_key]

        # Add the match
        buffer.append((entry.timestamp, entry))

        # Clean old entries outside the time window
        cutoff = entry.timestamp - timedelta(seconds=rule.time_window)
        buffer[:] = [(ts, e) for ts, e in buffer if ts >= cutoff]

        # Check if threshold is met
        if len(buffer) >= rule.threshold:
            # Generate detection
            self._create_detection(rule, buffer, group_key)
            # Clear buffer to avoid duplicate detections
            buffer.clear()

    def _create_detection(
        self,
        rule: Rule,
        events: list[tuple[datetime, LogEntry]],
        group_key: str
    ) -> Detection:
        """Create a Detection from matched events."""
        self._detection_counter += 1

        entries = [entry for _, entry in events]
        latest_timestamp = max(ts for ts, _ in events)

        # Calculate initial score (will be refined by RiskScorer)
        base_score = rule.severity * len(entries)

        # Determine severity label
        if rule.severity >= 8:
            severity_label = "Critical"
        elif rule.severity >= 6:
            severity_label = "High"
        elif rule.severity >= 4:
            severity_label = "Medium"
        else:
            severity_label = "Low"

        # Generate summary message
        if group_key != "global":
            message = f"{rule.name}: {len(entries)} events from {group_key} in {rule.time_window}s"
        else:
            message = f"{rule.name}: {len(entries)} events detected in {rule.time_window}s"

        detection = Detection(
            detection_id=f"DET-{self._detection_counter:06d}",
            rule_id=rule.rule_id,
            rule_name=rule.name,
            log_entries=entries,
            timestamp=latest_timestamp,
            score=base_score,
            severity=rule.severity,
            severity_label=severity_label,
            group_key=group_key,
            message=message,
        )

        self.detections.append(detection)
        logger.debug(f"Created detection: {detection.detection_id}")

        return detection

    def get_detections(self) -> list[Detection]:
        """Get all detections from the last evaluation."""
        return self.detections.copy()

    def get_detections_by_severity(self, min_severity: int = 1) -> list[Detection]:
        """Get detections filtered by minimum severity."""
        return [d for d in self.detections if d.severity >= min_severity]

    def get_detection_summary(self) -> dict:
        """Get a summary of detections by severity level."""
        summary = {
            "total": len(self.detections),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "by_rule": defaultdict(int),
        }

        for detection in self.detections:
            summary["by_rule"][detection.rule_id] += 1

            if detection.severity >= 8:
                summary["critical"] += 1
            elif detection.severity >= 6:
                summary["high"] += 1
            elif detection.severity >= 4:
                summary["medium"] += 1
            else:
                summary["low"] += 1

        summary["by_rule"] = dict(summary["by_rule"])
        return summary

    def clear(self) -> None:
        """Clear all detections and event buffers."""
        self.detections.clear()
        self._event_buffer.clear()
        self._detection_counter = 0

    def save_rules(self, config_path: str | Path) -> None:
        """
        Save current rules to a JSON configuration file.

        Args:
            config_path: Path to save the rules configuration
        """
        config_path = Path(config_path)

        rules_data = {
            "rules": [rule.to_dict() for rule in self.rules.values()]
        }

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(rules_data, f, indent=2)

        logger.info(f"Saved {len(self.rules)} rules to {config_path}")
