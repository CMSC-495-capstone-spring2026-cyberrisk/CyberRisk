"""
RiskScorer Module - Calculates risk scores and assigns severity levels.

Implements the risk scoring algorithm that aggregates detection events
into cumulative risk scores and categorizes them into severity levels.

Author: CyberRisk Team
"""

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from cyberrisk.core.rule_engine import Detection

logger = logging.getLogger(__name__)


@dataclass
class ScoredEvent:
    """
    Represents a detection with calculated risk score.

    Wraps a Detection with additional scoring information.
    """
    detection: Detection
    base_score: int
    frequency_multiplier: float
    context_multiplier: float
    final_score: int
    risk_level: str
    risk_category: str

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "detection_id": self.detection.detection_id,
            "rule_id": self.detection.rule_id,
            "rule_name": self.detection.rule_name,
            "timestamp": self.detection.timestamp.isoformat(),
            "base_score": self.base_score,
            "frequency_multiplier": round(self.frequency_multiplier, 2),
            "context_multiplier": round(self.context_multiplier, 2),
            "final_score": self.final_score,
            "risk_level": self.risk_level,
            "risk_category": self.risk_category,
            "group_key": self.detection.group_key,
            "message": self.detection.message,
        }


@dataclass
class RiskAssessment:
    """
    Overall risk assessment for analyzed logs.

    Aggregates all scored events into a comprehensive risk picture.
    """
    total_score: int
    risk_level: str
    risk_category: str
    scored_events: list[ScoredEvent]
    summary: dict
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "total_score": self.total_score,
            "risk_level": self.risk_level,
            "risk_category": self.risk_category,
            "timestamp": self.timestamp.isoformat(),
            "summary": self.summary,
            "event_count": len(self.scored_events),
            "events": [e.to_dict() for e in self.scored_events],
        }


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

    # Default risk level thresholds
    DEFAULT_THRESHOLDS = {
        "low": 25,
        "medium": 50,
        "high": 75,
    }

    # Severity weights for different event types
    DEFAULT_SEVERITY_WEIGHTS = {
        "authentication_failure": 1.2,
        "privilege_escalation": 1.5,
        "port_scan": 1.3,
        "file_access": 1.1,
        "network_connection": 1.0,
        "service_stop": 1.2,
        "unknown": 1.0,
    }

    # Context multipliers for specific patterns
    CONTEXT_PATTERNS = {
        "root": 1.5,
        "admin": 1.4,
        "password": 1.2,
        "sudo": 1.3,
        "ssh": 1.2,
        "/etc/shadow": 1.8,
        "/etc/passwd": 1.5,
        "0.0.0.0": 0.8,  # Local traffic is less concerning
        "127.0.0.1": 0.7,
    }

    def __init__(
        self,
        thresholds: Optional[dict] = None,
        severity_weights: Optional[dict] = None,
    ):
        """
        Initialize the RiskScorer.

        Args:
            thresholds: Custom risk level thresholds
            severity_weights: Custom severity weights by event type
        """
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS.copy()
        self.severity_weights = severity_weights or self.DEFAULT_SEVERITY_WEIGHTS.copy()
        self.scored_events: list[ScoredEvent] = []

    def score_detections(self, detections: list[Detection]) -> RiskAssessment:
        """
        Score a list of detections and produce a risk assessment.

        Args:
            detections: List of Detection objects to score

        Returns:
            RiskAssessment containing scored events and overall risk
        """
        self.scored_events = []

        for detection in detections:
            scored = self._score_detection(detection)
            self.scored_events.append(scored)

        # Calculate total risk score
        total_score = sum(e.final_score for e in self.scored_events)

        # Determine overall risk level
        risk_level, risk_category = self._categorize_score(total_score)

        # Generate summary statistics
        summary = self._generate_summary()

        assessment = RiskAssessment(
            total_score=total_score,
            risk_level=risk_level,
            risk_category=risk_category,
            scored_events=self.scored_events,
            summary=summary,
        )

        logger.info(
            f"Risk assessment complete: {risk_category} ({total_score} points) "
            f"from {len(detections)} detections"
        )

        return assessment

    def _score_detection(self, detection: Detection) -> ScoredEvent:
        """Calculate risk score for a single detection."""
        # Base score from rule severity (1-10)
        base_score = detection.severity

        # Frequency multiplier: log2(event_count + 1)
        event_count = len(detection.log_entries)
        frequency_multiplier = math.log2(event_count + 1)

        # Context multiplier based on message content
        context_multiplier = self._calculate_context_multiplier(detection)

        # Calculate final score
        final_score = int(base_score * frequency_multiplier * context_multiplier)

        # Ensure minimum score of 1
        final_score = max(1, final_score)

        # Categorize this individual event
        risk_level, risk_category = self._categorize_score(final_score)

        return ScoredEvent(
            detection=detection,
            base_score=base_score,
            frequency_multiplier=frequency_multiplier,
            context_multiplier=context_multiplier,
            final_score=final_score,
            risk_level=risk_level,
            risk_category=risk_category,
        )

    def _calculate_context_multiplier(self, detection: Detection) -> float:
        """Calculate context multiplier based on detection content."""
        multiplier = 1.0

        # Check detection message and log entries for context patterns
        text_to_check = detection.message.lower()

        for entry in detection.log_entries[:5]:  # Check first 5 entries
            text_to_check += " " + entry.message.lower()
            if entry.user:
                text_to_check += " " + entry.user.lower()

        # Apply context pattern multipliers
        for pattern, mult in self.CONTEXT_PATTERNS.items():
            if pattern.lower() in text_to_check:
                if mult > 1.0:
                    multiplier = max(multiplier, mult)  # Take highest increase
                else:
                    multiplier = min(multiplier, mult)  # Take lowest decrease

        # Apply event type weight
        if detection.log_entries:
            event_type = detection.log_entries[0].event_type
            type_weight = self.severity_weights.get(event_type, 1.0)
            multiplier *= type_weight

        return multiplier

    def _categorize_score(self, score: int) -> tuple[str, str]:
        """
        Categorize a score into risk level and category.

        Returns:
            Tuple of (numeric_level, category_name)
        """
        if score > self.thresholds["high"]:
            return "4", "Critical"
        elif score > self.thresholds["medium"]:
            return "3", "High"
        elif score > self.thresholds["low"]:
            return "2", "Medium"
        else:
            return "1", "Low"

    def _generate_summary(self) -> dict:
        """Generate summary statistics for scored events."""
        summary = {
            "total_events": len(self.scored_events),
            "total_score": sum(e.final_score for e in self.scored_events),
            "average_score": 0,
            "max_score": 0,
            "by_category": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
            },
            "by_rule": defaultdict(lambda: {"count": 0, "score": 0}),
            "top_sources": defaultdict(int),
            "timeline": [],
        }

        if not self.scored_events:
            return summary

        summary["average_score"] = summary["total_score"] // len(self.scored_events)
        summary["max_score"] = max(e.final_score for e in self.scored_events)

        for event in self.scored_events:
            # Count by category
            summary["by_category"][event.risk_category] += 1

            # Aggregate by rule
            rule_id = event.detection.rule_id
            summary["by_rule"][rule_id]["count"] += 1
            summary["by_rule"][rule_id]["score"] += event.final_score
            summary["by_rule"][rule_id]["name"] = event.detection.rule_name

            # Track source IPs
            if event.detection.group_key and event.detection.group_key != "global":
                summary["top_sources"][event.detection.group_key] += event.final_score

        # Convert defaultdicts to regular dicts for JSON serialization
        summary["by_rule"] = dict(summary["by_rule"])
        summary["top_sources"] = dict(
            sorted(summary["top_sources"].items(), key=lambda x: -x[1])[:10]
        )

        # Generate timeline (events per hour)
        if self.scored_events:
            timeline = defaultdict(int)
            for event in self.scored_events:
                hour_key = event.detection.timestamp.strftime("%Y-%m-%d %H:00")
                timeline[hour_key] += 1
            summary["timeline"] = [
                {"time": k, "count": v}
                for k, v in sorted(timeline.items())
            ]

        return summary

    def calculate_score(self, detection: Detection) -> int:
        """
        Calculate risk score for a single detection.

        Convenience method for scoring individual detections.

        Args:
            detection: Detection to score

        Returns:
            Calculated risk score
        """
        scored = self._score_detection(detection)
        return scored.final_score

    def assign_severity(self, score: int) -> str:
        """
        Assign severity category based on score.

        Args:
            score: Risk score value

        Returns:
            Severity category name (Critical, High, Medium, Low)
        """
        _, category = self._categorize_score(score)
        return category

    def aggregate_risk(self, detections: list[Detection]) -> int:
        """
        Calculate total risk score for multiple detections.

        Args:
            detections: List of detections to aggregate

        Returns:
            Total aggregated risk score
        """
        return sum(self.calculate_score(d) for d in detections)

    def categorize(self, score: int) -> str:
        """
        Categorize a score value.

        Args:
            score: Risk score to categorize

        Returns:
            Category name
        """
        return self.assign_severity(score)

    def get_scored_events(self) -> list[ScoredEvent]:
        """Return list of scored events from last assessment."""
        return self.scored_events.copy()

    def set_thresholds(
        self,
        low: Optional[int] = None,
        medium: Optional[int] = None,
        high: Optional[int] = None,
    ) -> None:
        """
        Update risk level thresholds.

        Args:
            low: Maximum score for Low risk
            medium: Maximum score for Medium risk
            high: Maximum score for High risk
        """
        if low is not None:
            self.thresholds["low"] = low
        if medium is not None:
            self.thresholds["medium"] = medium
        if high is not None:
            self.thresholds["high"] = high

    def get_thresholds(self) -> dict:
        """Return current risk thresholds."""
        return self.thresholds.copy()
