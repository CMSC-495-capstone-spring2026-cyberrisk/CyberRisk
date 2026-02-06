"""
Unit tests for the RiskScorer module.

Tests risk score calculations, severity categorization, score aggregation,
threshold configuration, and edge case handling.
"""

import math
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cyberrisk.core.log_parser import LogEntry
from cyberrisk.core.rule_engine import Detection
from cyberrisk.core.risk_scorer import RiskScorer, RiskAssessment, ScoredEvent


# ---------------------------------------------------------------------------
# Helpers – create lightweight Detection / LogEntry objects for testing
# ---------------------------------------------------------------------------

def _make_entry(
    message="Test event",
    event_type="unknown",
    source_ip=None,
    user=None,
    timestamp=None,
):
    """Create a LogEntry with sensible defaults for testing."""
    return LogEntry(
        timestamp=timestamp or datetime(2026, 1, 26, 10, 0, 0),
        message=message,
        event_type=event_type,
        source_ip=source_ip,
        user=user,
    )


def _make_detection(
    severity=5,
    entries=None,
    rule_id="TEST-001",
    rule_name="Test Rule",
    group_key="global",
    message="Test detection",
):
    """Create a Detection with sensible defaults for testing."""
    if entries is None:
        entries = [_make_entry()]
    return Detection(
        detection_id=f"DET-{id(entries):06d}",
        rule_id=rule_id,
        rule_name=rule_name,
        log_entries=entries,
        timestamp=entries[0].timestamp,
        severity=severity,
        group_key=group_key,
        message=message,
    )


# ===========================================================================
# Test class: ScoredEvent dataclass
# ===========================================================================

class TestScoredEvent:
    """Tests for the ScoredEvent dataclass."""

    def test_scored_event_to_dict(self):
        """Verify ScoredEvent.to_dict() includes all expected keys."""
        detection = _make_detection(severity=7)
        scored = ScoredEvent(
            detection=detection,
            base_score=7,
            frequency_multiplier=1.0,
            context_multiplier=1.0,
            final_score=7,
            risk_level="1",
            risk_category="Low",
        )
        data = scored.to_dict()

        assert data["detection_id"] == detection.detection_id
        assert data["base_score"] == 7
        assert data["final_score"] == 7
        assert data["risk_level"] == "1"
        assert data["risk_category"] == "Low"
        assert "timestamp" in data
        assert "message" in data

    def test_scored_event_multipliers_rounded(self):
        """Verify multipliers are rounded to 2 decimal places in dict output."""
        detection = _make_detection()
        scored = ScoredEvent(
            detection=detection,
            base_score=5,
            frequency_multiplier=1.58496,
            context_multiplier=1.23456,
            final_score=10,
            risk_level="1",
            risk_category="Low",
        )
        data = scored.to_dict()

        assert data["frequency_multiplier"] == 1.58
        assert data["context_multiplier"] == 1.23


# ===========================================================================
# Test class: RiskAssessment dataclass
# ===========================================================================

class TestRiskAssessment:
    """Tests for the RiskAssessment dataclass."""

    def test_risk_assessment_to_dict(self):
        """Verify RiskAssessment.to_dict() includes all expected keys."""
        assessment = RiskAssessment(
            total_score=42,
            risk_level="2",
            risk_category="Medium",
            scored_events=[],
            summary={"total_events": 0},
        )
        data = assessment.to_dict()

        assert data["total_score"] == 42
        assert data["risk_level"] == "2"
        assert data["risk_category"] == "Medium"
        assert data["event_count"] == 0
        assert isinstance(data["events"], list)
        assert "timestamp" in data

    def test_risk_assessment_default_timestamp(self):
        """Verify RiskAssessment gets a default timestamp when not provided."""
        assessment = RiskAssessment(
            total_score=0,
            risk_level="1",
            risk_category="Low",
            scored_events=[],
            summary={},
        )
        assert isinstance(assessment.timestamp, datetime)


# ===========================================================================
# Test class: RiskScorer – severity categorization
# ===========================================================================

class TestRiskScorerCategorization:
    """Tests for score-to-severity categorization with default thresholds."""

    def test_low_risk_at_boundary(self):
        """Score of exactly 25 is categorized as Low."""
        scorer = RiskScorer()
        assert scorer.assign_severity(25) == "Low"

    def test_low_risk_zero(self):
        """Score of 0 is categorized as Low."""
        scorer = RiskScorer()
        assert scorer.assign_severity(0) == "Low"

    def test_medium_risk_lower_boundary(self):
        """Score of 26 is categorized as Medium."""
        scorer = RiskScorer()
        assert scorer.assign_severity(26) == "Medium"

    def test_medium_risk_upper_boundary(self):
        """Score of 50 is categorized as Medium."""
        scorer = RiskScorer()
        assert scorer.assign_severity(50) == "Medium"

    def test_high_risk_lower_boundary(self):
        """Score of 51 is categorized as High."""
        scorer = RiskScorer()
        assert scorer.assign_severity(51) == "High"

    def test_high_risk_upper_boundary(self):
        """Score of 75 is categorized as High."""
        scorer = RiskScorer()
        assert scorer.assign_severity(75) == "High"

    def test_critical_risk_lower_boundary(self):
        """Score of 76 is categorized as Critical."""
        scorer = RiskScorer()
        assert scorer.assign_severity(76) == "Critical"

    def test_critical_risk_high_value(self):
        """Score of 100 is categorized as Critical."""
        scorer = RiskScorer()
        assert scorer.assign_severity(100) == "Critical"

    def test_categorize_alias(self):
        """The categorize() method is an alias for assign_severity()."""
        scorer = RiskScorer()
        assert scorer.categorize(30) == scorer.assign_severity(30)
        assert scorer.categorize(80) == scorer.assign_severity(80)


# ===========================================================================
# Test class: RiskScorer – custom thresholds
# ===========================================================================

class TestRiskScorerCustomThresholds:
    """Tests for custom risk-level thresholds (e.g. user-defined ranges)."""

    def test_custom_thresholds_via_constructor(self):
        """Custom thresholds passed at construction time are respected."""
        scorer = RiskScorer(thresholds={"low": 39, "medium": 79, "high": 100})

        # low range: 0-39
        assert scorer.assign_severity(0) == "Low"
        assert scorer.assign_severity(39) == "Low"
        # medium range: 40-79
        assert scorer.assign_severity(40) == "Medium"
        assert scorer.assign_severity(79) == "Medium"
        # high range: 80-100
        assert scorer.assign_severity(80) == "High"
        assert scorer.assign_severity(100) == "High"
        # critical: >100
        assert scorer.assign_severity(101) == "Critical"

    def test_set_thresholds(self):
        """set_thresholds() updates individual thresholds."""
        scorer = RiskScorer()
        scorer.set_thresholds(low=10, medium=30, high=60)

        assert scorer.assign_severity(10) == "Low"
        assert scorer.assign_severity(11) == "Medium"
        assert scorer.assign_severity(30) == "Medium"
        assert scorer.assign_severity(31) == "High"
        assert scorer.assign_severity(60) == "High"
        assert scorer.assign_severity(61) == "Critical"

    def test_set_thresholds_partial(self):
        """set_thresholds() can update only some thresholds."""
        scorer = RiskScorer()
        original = scorer.get_thresholds()
        scorer.set_thresholds(high=90)  # Only update high

        updated = scorer.get_thresholds()
        assert updated["low"] == original["low"]
        assert updated["medium"] == original["medium"]
        assert updated["high"] == 90

    def test_get_thresholds_returns_copy(self):
        """get_thresholds() returns a copy, not a reference to internal state."""
        scorer = RiskScorer()
        thresholds = scorer.get_thresholds()
        thresholds["low"] = 999
        assert scorer.get_thresholds()["low"] != 999


# ===========================================================================
# Test class: RiskScorer – single detection scoring
# ===========================================================================

class TestRiskScorerSingleDetection:
    """Tests for scoring individual detections via calculate_score()."""

    def test_single_entry_score(self):
        """A detection with one log entry uses log2(2) = 1.0 frequency multiplier."""
        detection = _make_detection(severity=5, entries=[_make_entry()])
        scorer = RiskScorer()
        score = scorer.calculate_score(detection)

        # base=5, freq=log2(1+1)=1.0, context~1.0 → int(5*1.0*1.0) = 5
        assert score >= 1  # Minimum score guarantee
        assert isinstance(score, int)

    def test_multiple_entries_increase_score(self):
        """More log entries increase the frequency multiplier and thus the score."""
        entries_1 = [_make_entry()]
        entries_5 = [_make_entry() for _ in range(5)]

        det_1 = _make_detection(severity=5, entries=entries_1)
        det_5 = _make_detection(severity=5, entries=entries_5)

        scorer = RiskScorer()
        score_1 = scorer.calculate_score(det_1)
        score_5 = scorer.calculate_score(det_5)

        assert score_5 > score_1

    def test_higher_severity_gives_higher_score(self):
        """Detections with higher severity produce higher scores (same entry count)."""
        det_low = _make_detection(severity=2, entries=[_make_entry()])
        det_high = _make_detection(severity=9, entries=[_make_entry()])

        scorer = RiskScorer()
        assert scorer.calculate_score(det_high) > scorer.calculate_score(det_low)

    def test_minimum_score_is_one(self):
        """Final score is always at least 1."""
        det = _make_detection(severity=1, entries=[_make_entry(message="127.0.0.1")])
        scorer = RiskScorer()
        score = scorer.calculate_score(det)
        assert score >= 1

    def test_context_multiplier_root_keyword(self):
        """Messages containing 'root' receive a higher context multiplier."""
        normal = _make_detection(
            severity=5,
            entries=[_make_entry(message="Normal event")],
            message="Normal event",
        )
        root_event = _make_detection(
            severity=5,
            entries=[_make_entry(message="root login detected", user="root")],
            message="root login detected",
        )

        scorer = RiskScorer()
        assert scorer.calculate_score(root_event) >= scorer.calculate_score(normal)

    def test_context_multiplier_etc_shadow(self):
        """Messages referencing /etc/shadow receive a high context multiplier."""
        normal = _make_detection(
            severity=5,
            entries=[_make_entry(message="File read operation")],
        )
        shadow_event = _make_detection(
            severity=5,
            entries=[_make_entry(message="Read /etc/shadow")],
        )

        scorer = RiskScorer()
        assert scorer.calculate_score(shadow_event) >= scorer.calculate_score(normal)

    def test_context_multiplier_localhost_reduces_score(self):
        """Messages with 127.0.0.1 receive a lower context multiplier."""
        remote = _make_detection(
            severity=5,
            entries=[_make_entry(message="Connection from 192.168.1.1")],
        )
        local = _make_detection(
            severity=5,
            entries=[_make_entry(message="Connection from 127.0.0.1")],
        )

        scorer = RiskScorer()
        assert scorer.calculate_score(local) <= scorer.calculate_score(remote)

    def test_event_type_weight_authentication_failure(self):
        """Event type 'authentication_failure' has weight 1.2."""
        default_type = _make_detection(
            severity=5,
            entries=[_make_entry(event_type="unknown", message="event")],
        )
        auth_fail = _make_detection(
            severity=5,
            entries=[_make_entry(event_type="authentication_failure", message="event")],
        )

        scorer = RiskScorer()
        assert scorer.calculate_score(auth_fail) >= scorer.calculate_score(default_type)

    def test_event_type_weight_privilege_escalation(self):
        """Event type 'privilege_escalation' has the highest weight (1.5)."""
        default_type = _make_detection(
            severity=5,
            entries=[_make_entry(event_type="unknown", message="event")],
        )
        priv_esc = _make_detection(
            severity=5,
            entries=[_make_entry(event_type="privilege_escalation", message="event")],
        )

        scorer = RiskScorer()
        assert scorer.calculate_score(priv_esc) >= scorer.calculate_score(default_type)


# ===========================================================================
# Test class: RiskScorer – aggregation
# ===========================================================================

class TestRiskScorerAggregation:
    """Tests for aggregate_risk() and score_detections()."""

    def test_aggregate_risk_sums_scores(self):
        """aggregate_risk() returns the sum of individual detection scores."""
        detections = [
            _make_detection(severity=5, entries=[_make_entry()]),
            _make_detection(severity=5, entries=[_make_entry()]),
        ]
        scorer = RiskScorer()
        total = scorer.aggregate_risk(detections)

        individual_sum = sum(scorer.calculate_score(d) for d in detections)
        assert total == individual_sum

    def test_aggregate_risk_empty_list(self):
        """aggregate_risk() returns 0 for an empty detection list."""
        scorer = RiskScorer()
        assert scorer.aggregate_risk([]) == 0

    def test_aggregate_risk_single_detection(self):
        """aggregate_risk() with one detection equals its individual score."""
        det = _make_detection(severity=7, entries=[_make_entry()])
        scorer = RiskScorer()
        assert scorer.aggregate_risk([det]) == scorer.calculate_score(det)

    def test_score_detections_returns_assessment(self):
        """score_detections() returns a RiskAssessment object."""
        detections = [_make_detection(severity=5)]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        assert isinstance(assessment, RiskAssessment)
        assert assessment.total_score > 0
        assert len(assessment.scored_events) == 1

    def test_score_detections_total_matches_sum(self):
        """Total score in assessment equals sum of all scored event final_scores."""
        detections = [
            _make_detection(severity=3, entries=[_make_entry()]),
            _make_detection(severity=7, entries=[_make_entry(), _make_entry()]),
            _make_detection(severity=5, entries=[_make_entry()]),
        ]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        expected_total = sum(e.final_score for e in assessment.scored_events)
        assert assessment.total_score == expected_total

    def test_score_detections_categorizes_overall_risk(self):
        """Overall risk category is derived from total score."""
        # Create enough high-severity detections to exceed critical threshold
        entries = [_make_entry() for _ in range(10)]
        detections = [
            _make_detection(severity=9, entries=entries),
            _make_detection(severity=8, entries=entries),
            _make_detection(severity=9, entries=entries),
        ]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        assert assessment.total_score > 75
        assert assessment.risk_category == "Critical"

    def test_low_severity_produces_low_category(self):
        """A single low-severity detection with one entry stays in Low category."""
        det = _make_detection(severity=2, entries=[_make_entry()])
        scorer = RiskScorer()
        assessment = scorer.score_detections([det])

        assert assessment.total_score <= 25
        assert assessment.risk_category == "Low"


# ===========================================================================
# Test class: RiskScorer – summary generation
# ===========================================================================

class TestRiskScorerSummary:
    """Tests for the summary statistics generated by score_detections()."""

    def test_summary_total_events(self):
        """Summary reports correct total event count."""
        detections = [
            _make_detection(severity=5, entries=[_make_entry()]),
            _make_detection(severity=3, entries=[_make_entry()]),
        ]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        assert assessment.summary["total_events"] == 2

    def test_summary_by_category_counts(self):
        """Summary counts events by risk category."""
        detections = [_make_detection(severity=3, entries=[_make_entry()])]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        by_cat = assessment.summary["by_category"]
        total = sum(by_cat.values())
        assert total == len(detections)

    def test_summary_max_score(self):
        """Summary reports correct maximum score."""
        detections = [
            _make_detection(severity=2, entries=[_make_entry()]),
            _make_detection(severity=8, entries=[_make_entry(), _make_entry()]),
        ]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        individual_scores = [e.final_score for e in assessment.scored_events]
        assert assessment.summary["max_score"] == max(individual_scores)

    def test_summary_average_score(self):
        """Summary reports correct average score (integer division)."""
        detections = [
            _make_detection(severity=4, entries=[_make_entry()]),
            _make_detection(severity=6, entries=[_make_entry()]),
        ]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        expected_avg = assessment.summary["total_score"] // len(assessment.scored_events)
        assert assessment.summary["average_score"] == expected_avg

    def test_summary_by_rule(self):
        """Summary aggregates scores per rule_id."""
        detections = [
            _make_detection(severity=5, rule_id="R1", rule_name="Rule 1"),
            _make_detection(severity=3, rule_id="R1", rule_name="Rule 1"),
            _make_detection(severity=7, rule_id="R2", rule_name="Rule 2"),
        ]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        by_rule = assessment.summary["by_rule"]
        assert "R1" in by_rule
        assert "R2" in by_rule
        assert by_rule["R1"]["count"] == 2
        assert by_rule["R2"]["count"] == 1

    def test_summary_top_sources(self):
        """Summary tracks top risk sources from group_key."""
        detections = [
            _make_detection(severity=5, group_key="192.168.1.100"),
            _make_detection(severity=8, group_key="10.0.0.50"),
        ]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        top_sources = assessment.summary["top_sources"]
        assert "192.168.1.100" in top_sources
        assert "10.0.0.50" in top_sources

    def test_summary_excludes_global_from_sources(self):
        """Detections with group_key 'global' are excluded from top_sources."""
        detections = [
            _make_detection(severity=5, group_key="global"),
        ]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        assert "global" not in assessment.summary["top_sources"]

    def test_summary_timeline(self):
        """Summary includes a timeline of events per hour."""
        entries_h1 = [_make_entry(timestamp=datetime(2026, 1, 26, 10, 0, 0))]
        entries_h2 = [_make_entry(timestamp=datetime(2026, 1, 26, 11, 0, 0))]

        detections = [
            _make_detection(severity=5, entries=entries_h1),
            _make_detection(severity=5, entries=entries_h2),
        ]
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        timeline = assessment.summary["timeline"]
        assert len(timeline) == 2
        assert all("time" in t and "count" in t for t in timeline)


# ===========================================================================
# Test class: RiskScorer – get_scored_events
# ===========================================================================

class TestGetScoredEvents:
    """Tests for get_scored_events() method."""

    def test_returns_copy(self):
        """get_scored_events() returns a copy, not the internal list."""
        scorer = RiskScorer()
        scorer.score_detections([_make_detection(severity=5)])

        events = scorer.get_scored_events()
        events.clear()
        assert len(scorer.get_scored_events()) == 1

    def test_empty_before_scoring(self):
        """get_scored_events() returns empty list before any scoring."""
        scorer = RiskScorer()
        assert scorer.get_scored_events() == []

    def test_reset_on_new_scoring(self):
        """Calling score_detections() resets the scored events list."""
        scorer = RiskScorer()
        scorer.score_detections([_make_detection(severity=5)])
        assert len(scorer.get_scored_events()) == 1

        scorer.score_detections([_make_detection(severity=3), _make_detection(severity=4)])
        assert len(scorer.get_scored_events()) == 2


# ===========================================================================
# Test class: RiskScorer – edge cases
# ===========================================================================

class TestRiskScorerEdgeCases:
    """Tests for edge cases: empty data, boundary values, unusual inputs."""

    def test_empty_detections_list(self):
        """score_detections() handles an empty list gracefully."""
        scorer = RiskScorer()
        assessment = scorer.score_detections([])

        assert assessment.total_score == 0
        assert assessment.risk_category == "Low"
        assert len(assessment.scored_events) == 0
        assert assessment.summary["total_events"] == 0

    def test_detection_with_many_entries(self):
        """Scoring works with a large number of log entries."""
        entries = [_make_entry() for _ in range(100)]
        det = _make_detection(severity=5, entries=entries)

        scorer = RiskScorer()
        score = scorer.calculate_score(det)
        assert score > 0
        assert isinstance(score, int)

    def test_detection_severity_minimum(self):
        """A detection with severity 1 still produces a valid score."""
        det = _make_detection(severity=1)
        scorer = RiskScorer()
        score = scorer.calculate_score(det)
        assert score >= 1

    def test_detection_severity_maximum(self):
        """A detection with severity 10 scores correctly."""
        det = _make_detection(severity=10)
        scorer = RiskScorer()
        score = scorer.calculate_score(det)
        assert score >= 10  # base 10 * freq >= 1.0

    def test_frequency_multiplier_formula(self):
        """Verify the frequency multiplier matches log2(count + 1)."""
        entries = [_make_entry(event_type="unknown", message="plain") for _ in range(4)]
        det = _make_detection(severity=5, entries=entries, message="plain")

        scorer = RiskScorer()
        assessment = scorer.score_detections([det])
        scored = assessment.scored_events[0]

        expected_freq = math.log2(4 + 1)  # log2(5) ≈ 2.322
        assert abs(scored.frequency_multiplier - expected_freq) < 0.001

    def test_custom_severity_weights(self):
        """Custom severity weights override defaults."""
        custom_weights = {"authentication_failure": 2.0, "unknown": 1.0}
        scorer = RiskScorer(severity_weights=custom_weights)

        det = _make_detection(
            severity=5,
            entries=[_make_entry(event_type="authentication_failure", message="event")],
        )
        score_custom = scorer.calculate_score(det)

        scorer_default = RiskScorer()
        score_default = scorer_default.calculate_score(det)

        # Custom weight 2.0 > default 1.2, so custom score should be higher
        assert score_custom >= score_default

    def test_negative_score_clamped_to_one(self):
        """Even with very low multipliers, score is clamped to at least 1."""
        scorer = RiskScorer()
        det = _make_detection(
            severity=1,
            entries=[_make_entry(message="127.0.0.1 local traffic")],
        )
        score = scorer.calculate_score(det)
        assert score >= 1

    def test_scoring_preserves_detection_reference(self):
        """ScoredEvent retains a reference to the original Detection."""
        det = _make_detection(severity=5)
        scorer = RiskScorer()
        assessment = scorer.score_detections([det])

        scored = assessment.scored_events[0]
        assert scored.detection is det
        assert scored.detection.rule_id == det.rule_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
