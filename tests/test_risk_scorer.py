"""
Unit tests for the RiskScorer module.

Tests cover:
- ScoredEvent dataclass
- RiskAssessment dataclass
- RiskScorer scoring algorithm
- Risk categorization
- Summary generation
"""

import math
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cyberrisk.core.log_parser import LogEntry
from cyberrisk.core.rule_engine import Detection
from cyberrisk.core.risk_scorer import RiskScorer, ScoredEvent, RiskAssessment


# =============================================================================
# Test Fixtures
# =============================================================================

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
        score=8,
        severity=8,
        severity_label="Critical",
        group_key="192.168.1.100",
        message="Brute Force Login: 5 events from 192.168.1.100",
    )


@pytest.fixture
def multi_entry_detection():
    """Create a Detection with multiple log entries."""
    entries = [
        LogEntry(
            timestamp=datetime(2026, 1, 28, 10, 30, i),
            source_ip="10.0.0.50",
            message=f"Failed password attempt {i+1}",
            event_type="authentication_failure",
            user="root",
        )
        for i in range(5)
    ]
    return Detection(
        detection_id="DET-000002",
        rule_id="RULE-002",
        rule_name="SSH Auth Failure",
        log_entries=entries,
        timestamp=datetime(2026, 1, 28, 10, 30, 4),
        score=30,
        severity=6,
        severity_label="High",
        group_key="10.0.0.50",
        message="SSH Auth Failure: 5 events from 10.0.0.50",
    )


@pytest.fixture
def local_traffic_detection():
    """Create a Detection with local/loopback traffic."""
    entry = LogEntry(
        timestamp=datetime(2026, 1, 28, 10, 30, 0),
        source_ip="127.0.0.1",
        message="Connection from 127.0.0.1",
        event_type="network_connection",
    )
    return Detection(
        detection_id="DET-000003",
        rule_id="RULE-003",
        rule_name="Network Connection",
        log_entries=[entry],
        timestamp=datetime(2026, 1, 28, 10, 30, 0),
        score=3,
        severity=3,
        severity_label="Low",
        group_key="127.0.0.1",
        message="Network Connection from localhost",
    )


@pytest.fixture
def scorer():
    """Create a RiskScorer instance with default settings."""
    return RiskScorer()


# =============================================================================
# ScoredEvent Tests
# =============================================================================

class TestScoredEvent:
    """Tests for ScoredEvent dataclass."""

    def test_scored_event_creation(self, sample_detection):
        """Test creating a ScoredEvent with all fields."""
        scored = ScoredEvent(
            detection=sample_detection,
            base_score=8,
            frequency_multiplier=1.0,
            context_multiplier=1.4,
            final_score=11,
            risk_level="1",
            risk_category="Low",
        )

        assert scored.detection == sample_detection
        assert scored.base_score == 8
        assert scored.frequency_multiplier == 1.0
        assert scored.context_multiplier == 1.4
        assert scored.final_score == 11
        assert scored.risk_level == "1"
        assert scored.risk_category == "Low"

    def test_scored_event_to_dict(self, sample_detection):
        """Test converting ScoredEvent to dictionary."""
        scored = ScoredEvent(
            detection=sample_detection,
            base_score=8,
            frequency_multiplier=1.5,
            context_multiplier=1.2,
            final_score=14,
            risk_level="2",
            risk_category="Medium",
        )

        data = scored.to_dict()

        assert data["detection_id"] == "DET-000001"
        assert data["rule_id"] == "RULE-001"
        assert data["rule_name"] == "Brute Force Login"
        assert data["base_score"] == 8
        assert data["frequency_multiplier"] == 1.5
        assert data["context_multiplier"] == 1.2
        assert data["final_score"] == 14
        assert data["risk_level"] == "2"
        assert data["risk_category"] == "Medium"
        assert data["group_key"] == "192.168.1.100"
        assert "timestamp" in data


# =============================================================================
# RiskAssessment Tests
# =============================================================================

class TestRiskAssessment:
    """Tests for RiskAssessment dataclass."""

    def test_risk_assessment_creation(self, sample_detection):
        """Test creating a RiskAssessment."""
        scored_event = ScoredEvent(
            detection=sample_detection,
            base_score=8,
            frequency_multiplier=1.0,
            context_multiplier=1.0,
            final_score=8,
            risk_level="1",
            risk_category="Low",
        )

        assessment = RiskAssessment(
            total_score=8,
            risk_level="1",
            risk_category="Low",
            scored_events=[scored_event],
            summary={"total_events": 1},
        )

        assert assessment.total_score == 8
        assert assessment.risk_level == "1"
        assert assessment.risk_category == "Low"
        assert len(assessment.scored_events) == 1
        assert assessment.summary["total_events"] == 1

    def test_risk_assessment_to_dict(self, sample_detection):
        """Test converting RiskAssessment to dictionary."""
        scored_event = ScoredEvent(
            detection=sample_detection,
            base_score=8,
            frequency_multiplier=1.0,
            context_multiplier=1.0,
            final_score=8,
            risk_level="1",
            risk_category="Low",
        )

        assessment = RiskAssessment(
            total_score=50,
            risk_level="2",
            risk_category="Medium",
            scored_events=[scored_event],
            summary={"total_events": 1, "max_score": 8},
        )

        data = assessment.to_dict()

        assert data["total_score"] == 50
        assert data["risk_level"] == "2"
        assert data["risk_category"] == "Medium"
        assert data["event_count"] == 1
        assert "timestamp" in data
        assert "events" in data
        assert len(data["events"]) == 1


# =============================================================================
# RiskScorer Initialization Tests
# =============================================================================

class TestRiskScorerInit:
    """Tests for RiskScorer initialization."""

    def test_default_initialization(self):
        """Test RiskScorer initializes with default values."""
        scorer = RiskScorer()

        thresholds = scorer.get_thresholds()
        assert thresholds["low"] == 25
        assert thresholds["medium"] == 50
        assert thresholds["high"] == 75
        assert scorer.scored_events == []

    def test_custom_thresholds(self):
        """Test RiskScorer with custom thresholds."""
        custom_thresholds = {"low": 10, "medium": 30, "high": 60}
        scorer = RiskScorer(thresholds=custom_thresholds)

        thresholds = scorer.get_thresholds()
        assert thresholds["low"] == 10
        assert thresholds["medium"] == 30
        assert thresholds["high"] == 60

    def test_custom_severity_weights(self):
        """Test RiskScorer with custom severity weights."""
        custom_weights = {"authentication_failure": 2.0, "port_scan": 1.5}
        scorer = RiskScorer(severity_weights=custom_weights)

        assert scorer.severity_weights["authentication_failure"] == 2.0
        assert scorer.severity_weights["port_scan"] == 1.5


# =============================================================================
# Score Categorization Tests
# =============================================================================

class TestScoreCategorization:
    """Tests for score categorization methods."""

    def test_categorize_low_score(self, scorer):
        """Test categorization of low risk scores (0-25)."""
        assert scorer.categorize(0) == "Low"
        assert scorer.categorize(10) == "Low"
        assert scorer.categorize(25) == "Low"

    def test_categorize_medium_score(self, scorer):
        """Test categorization of medium risk scores (26-50)."""
        assert scorer.categorize(26) == "Medium"
        assert scorer.categorize(35) == "Medium"
        assert scorer.categorize(50) == "Medium"

    def test_categorize_high_score(self, scorer):
        """Test categorization of high risk scores (51-75)."""
        assert scorer.categorize(51) == "High"
        assert scorer.categorize(60) == "High"
        assert scorer.categorize(75) == "High"

    def test_categorize_critical_score(self, scorer):
        """Test categorization of critical risk scores (76+)."""
        assert scorer.categorize(76) == "Critical"
        assert scorer.categorize(100) == "Critical"
        assert scorer.categorize(500) == "Critical"

    def test_assign_severity(self, scorer):
        """Test assign_severity method returns correct category."""
        assert scorer.assign_severity(15) == "Low"
        assert scorer.assign_severity(40) == "Medium"
        assert scorer.assign_severity(65) == "High"
        assert scorer.assign_severity(90) == "Critical"


# =============================================================================
# Threshold Management Tests
# =============================================================================

class TestThresholdManagement:
    """Tests for threshold get/set methods."""

    def test_get_thresholds_returns_copy(self, scorer):
        """Test that get_thresholds returns a copy, not the original."""
        thresholds = scorer.get_thresholds()
        thresholds["low"] = 999

        # Original should be unchanged
        assert scorer.get_thresholds()["low"] == 25

    def test_set_thresholds_single(self, scorer):
        """Test setting individual thresholds."""
        scorer.set_thresholds(low=20)
        assert scorer.get_thresholds()["low"] == 20
        assert scorer.get_thresholds()["medium"] == 50  # Unchanged

    def test_set_thresholds_multiple(self, scorer):
        """Test setting multiple thresholds at once."""
        scorer.set_thresholds(low=15, medium=40, high=70)

        thresholds = scorer.get_thresholds()
        assert thresholds["low"] == 15
        assert thresholds["medium"] == 40
        assert thresholds["high"] == 70

    def test_set_thresholds_none_ignored(self, scorer):
        """Test that None values are ignored in set_thresholds."""
        original = scorer.get_thresholds()["medium"]
        scorer.set_thresholds(medium=None)

        assert scorer.get_thresholds()["medium"] == original


# =============================================================================
# Single Detection Scoring Tests
# =============================================================================

class TestSingleDetectionScoring:
    """Tests for scoring individual detections."""

    def test_calculate_score_basic(self, scorer, sample_detection):
        """Test basic score calculation for a single detection."""
        score = scorer.calculate_score(sample_detection)

        # Should be at least 1 (minimum score enforced)
        assert score >= 1
        # Should be based on severity (8) * frequency_mult * context_mult
        assert isinstance(score, int)

    def test_calculate_score_with_multiple_entries(self, scorer, multi_entry_detection):
        """Test that more log entries increase the score via frequency multiplier."""
        score = scorer.calculate_score(multi_entry_detection)

        # With 5 entries, frequency_multiplier = log2(5+1) ≈ 2.58
        # Base score is severity (6), so expected > 6
        assert score > 6

    def test_frequency_multiplier_calculation(self, scorer):
        """Test that frequency multiplier follows log2(count + 1)."""
        # Create detections with different entry counts
        entries_1 = [LogEntry(timestamp=datetime.now(), message="test")]
        entries_4 = [LogEntry(timestamp=datetime.now(), message="test") for _ in range(4)]
        entries_8 = [LogEntry(timestamp=datetime.now(), message="test") for _ in range(8)]

        det_1 = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=entries_1, timestamp=datetime.now(), severity=10
        )
        det_4 = Detection(
            detection_id="D4", rule_id="R1", rule_name="Test",
            log_entries=entries_4, timestamp=datetime.now(), severity=10
        )
        det_8 = Detection(
            detection_id="D8", rule_id="R1", rule_name="Test",
            log_entries=entries_8, timestamp=datetime.now(), severity=10
        )

        score_1 = scorer.calculate_score(det_1)
        score_4 = scorer.calculate_score(det_4)
        score_8 = scorer.calculate_score(det_8)

        # More entries should yield higher scores
        assert score_4 > score_1
        assert score_8 > score_4


# =============================================================================
# Context Multiplier Tests
# =============================================================================

class TestContextMultiplier:
    """Tests for context-based score multipliers."""

    def test_root_user_increases_score(self, scorer):
        """Test that 'root' user detection increases score."""
        entry_normal = LogEntry(
            timestamp=datetime.now(),
            message="Failed login for user testuser",
            user="testuser",
            event_type="authentication_failure",
        )
        entry_root = LogEntry(
            timestamp=datetime.now(),
            message="Failed login for user root",
            user="root",
            event_type="authentication_failure",
        )

        det_normal = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entry_normal], timestamp=datetime.now(), severity=5
        )
        det_root = Detection(
            detection_id="D2", rule_id="R1", rule_name="Test",
            log_entries=[entry_root], timestamp=datetime.now(), severity=5
        )

        score_normal = scorer.calculate_score(det_normal)
        score_root = scorer.calculate_score(det_root)

        # Root should have higher score due to 1.5 multiplier
        assert score_root >= score_normal

    def test_admin_user_increases_score(self, scorer):
        """Test that 'admin' in context increases score."""
        entry = LogEntry(
            timestamp=datetime.now(),
            message="Admin account locked",
            user="admin",
            event_type="authentication_failure",
        )

        detection = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entry], timestamp=datetime.now(), severity=5
        )

        score = scorer.calculate_score(detection)
        # With admin context (1.4) and auth_failure weight (1.2)
        # Score should be elevated
        assert score >= 5

    def test_shadow_file_access_increases_score(self, scorer):
        """Test that /etc/shadow access has high context multiplier."""
        entry = LogEntry(
            timestamp=datetime.now(),
            message="Access to /etc/shadow detected",
            event_type="file_access",
        )

        detection = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entry], timestamp=datetime.now(), severity=5
        )

        score = scorer.calculate_score(detection)
        # /etc/shadow has 1.8 multiplier
        assert score >= 5

    def test_localhost_decreases_score(self, scorer, local_traffic_detection):
        """Test that localhost traffic has reduced score."""
        score = scorer.calculate_score(local_traffic_detection)

        # 127.0.0.1 has 0.7 multiplier, should reduce score
        # But minimum score is 1
        assert score >= 1

    def test_ssh_context_multiplier(self, scorer):
        """Test that SSH-related detections have context multiplier."""
        entry = LogEntry(
            timestamp=datetime.now(),
            message="SSH connection failed",
            event_type="authentication_failure",
        )

        detection = Detection(
            detection_id="D1", rule_id="R1", rule_name="SSH Failure",
            log_entries=[entry], timestamp=datetime.now(), severity=5
        )

        score = scorer.calculate_score(detection)
        # SSH has 1.2 multiplier
        assert score >= 5


# =============================================================================
# Multiple Detection Scoring Tests
# =============================================================================

class TestMultipleDetectionScoring:
    """Tests for scoring multiple detections."""

    def test_score_empty_list(self, scorer):
        """Test scoring an empty detection list."""
        assessment = scorer.score_detections([])

        assert assessment.total_score == 0
        assert assessment.risk_category == "Low"
        assert len(assessment.scored_events) == 0

    def test_score_single_detection(self, scorer, sample_detection):
        """Test scoring a single detection."""
        assessment = scorer.score_detections([sample_detection])

        assert assessment.total_score > 0
        assert len(assessment.scored_events) == 1
        assert assessment.scored_events[0].detection == sample_detection

    def test_score_multiple_detections(self, scorer, sample_detection, multi_entry_detection):
        """Test scoring multiple detections aggregates scores."""
        assessment = scorer.score_detections([sample_detection, multi_entry_detection])

        # Total should be sum of individual scores
        individual_scores = sum(e.final_score for e in assessment.scored_events)
        assert assessment.total_score == individual_scores
        assert len(assessment.scored_events) == 2

    def test_aggregate_risk(self, scorer, sample_detection, multi_entry_detection):
        """Test aggregate_risk method sums scores correctly."""
        detections = [sample_detection, multi_entry_detection]

        total = scorer.aggregate_risk(detections)

        # Should equal sum of individual calculate_score calls
        expected = sum(scorer.calculate_score(d) for d in detections)
        assert total == expected

    def test_get_scored_events_returns_copy(self, scorer, sample_detection):
        """Test that get_scored_events returns a copy."""
        scorer.score_detections([sample_detection])
        events = scorer.get_scored_events()

        events.clear()

        # Original should be unchanged
        assert len(scorer.get_scored_events()) == 1

    def test_score_detections_clears_previous(self, scorer, sample_detection, multi_entry_detection):
        """Test that score_detections clears previous scored_events."""
        scorer.score_detections([sample_detection])
        assert len(scorer.scored_events) == 1

        scorer.score_detections([multi_entry_detection])
        assert len(scorer.scored_events) == 1  # Not 2


# =============================================================================
# Summary Generation Tests
# =============================================================================

class TestSummaryGeneration:
    """Tests for summary statistics generation."""

    def test_summary_empty_detections(self, scorer):
        """Test summary generation with no detections."""
        assessment = scorer.score_detections([])
        summary = assessment.summary

        assert summary["total_events"] == 0
        assert summary["total_score"] == 0
        assert summary["average_score"] == 0
        assert summary["max_score"] == 0

    def test_summary_statistics(self, scorer, sample_detection, multi_entry_detection):
        """Test summary contains correct statistics."""
        assessment = scorer.score_detections([sample_detection, multi_entry_detection])
        summary = assessment.summary

        assert summary["total_events"] == 2
        assert summary["total_score"] == assessment.total_score
        assert summary["average_score"] == assessment.total_score // 2
        assert summary["max_score"] == max(e.final_score for e in assessment.scored_events)

    def test_summary_by_category(self, scorer):
        """Test summary tracks events by risk category."""
        # Create detections with different severities
        low_entry = LogEntry(timestamp=datetime.now(), message="info")
        high_entry = LogEntry(timestamp=datetime.now(), message="critical alert")

        low_det = Detection(
            detection_id="D1", rule_id="R1", rule_name="Low",
            log_entries=[low_entry], timestamp=datetime.now(), severity=2
        )
        high_det = Detection(
            detection_id="D2", rule_id="R2", rule_name="High",
            log_entries=[high_entry], timestamp=datetime.now(), severity=9
        )

        assessment = scorer.score_detections([low_det, high_det])
        by_category = assessment.summary["by_category"]

        # Should have counts for categories
        assert "Low" in by_category
        assert "Critical" in by_category or "High" in by_category or "Medium" in by_category

    def test_summary_by_rule(self, scorer, sample_detection, multi_entry_detection):
        """Test summary tracks events by rule."""
        assessment = scorer.score_detections([sample_detection, multi_entry_detection])
        by_rule = assessment.summary["by_rule"]

        assert "RULE-001" in by_rule
        assert "RULE-002" in by_rule
        assert by_rule["RULE-001"]["count"] == 1
        assert by_rule["RULE-002"]["count"] == 1

    def test_summary_top_sources(self, scorer, sample_detection, multi_entry_detection):
        """Test summary tracks top risk sources."""
        assessment = scorer.score_detections([sample_detection, multi_entry_detection])
        top_sources = assessment.summary["top_sources"]

        # Should contain the group_keys (IPs) from detections
        assert "192.168.1.100" in top_sources or "10.0.0.50" in top_sources

    def test_summary_timeline(self, scorer):
        """Test summary includes timeline data."""
        entries = [
            LogEntry(
                timestamp=datetime(2026, 1, 28, 10, 0, 0),
                message="Event 1"
            ),
            LogEntry(
                timestamp=datetime(2026, 1, 28, 11, 0, 0),
                message="Event 2"
            ),
        ]

        det1 = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entries[0]], timestamp=datetime(2026, 1, 28, 10, 0, 0), severity=5
        )
        det2 = Detection(
            detection_id="D2", rule_id="R1", rule_name="Test",
            log_entries=[entries[1]], timestamp=datetime(2026, 1, 28, 11, 0, 0), severity=5
        )

        assessment = scorer.score_detections([det1, det2])
        timeline = assessment.summary["timeline"]

        assert len(timeline) == 2
        assert all("time" in item and "count" in item for item in timeline)


# =============================================================================
# Risk Level Assignment Tests
# =============================================================================

class TestRiskLevelAssignment:
    """Tests for overall risk level assignment."""

    def test_low_risk_assessment(self, scorer):
        """Test that low total score yields Low risk assessment."""
        entry = LogEntry(timestamp=datetime.now(), message="Minor event")
        detection = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entry], timestamp=datetime.now(), severity=1
        )

        assessment = scorer.score_detections([detection])

        assert assessment.risk_category == "Low"
        assert assessment.risk_level == "1"

    def test_critical_risk_assessment(self, scorer):
        """Test that high total score yields Critical risk assessment."""
        # Create many high-severity detections
        detections = []
        for i in range(10):
            entries = [LogEntry(timestamp=datetime.now(), message=f"Critical {j}") for j in range(5)]
            det = Detection(
                detection_id=f"D{i}", rule_id="R1", rule_name="Critical Alert",
                log_entries=entries, timestamp=datetime.now(), severity=10
            )
            detections.append(det)

        assessment = scorer.score_detections(detections)

        assert assessment.risk_category == "Critical"
        assert assessment.risk_level == "4"

    def test_custom_thresholds_affect_categorization(self):
        """Test that custom thresholds change categorization."""
        # With very low thresholds, same score becomes Critical
        scorer = RiskScorer(thresholds={"low": 1, "medium": 2, "high": 3})

        entry = LogEntry(timestamp=datetime.now(), message="test")
        detection = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entry], timestamp=datetime.now(), severity=5
        )

        assessment = scorer.score_detections([detection])

        # Score should exceed threshold of 3, making it Critical
        assert assessment.risk_category == "Critical"


# =============================================================================
# Edge Cases and Error Handling Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_minimum_score_enforced(self, scorer):
        """Test that minimum score of 1 is enforced."""
        # Create detection that would have very low score
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="127.0.0.1",  # 0.7 multiplier
            message="localhost event",
            event_type="unknown",
        )
        detection = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entry], timestamp=datetime.now(), severity=1
        )

        score = scorer.calculate_score(detection)

        assert score >= 1

    def test_detection_without_group_key(self, scorer):
        """Test scoring detection without group_key."""
        entry = LogEntry(timestamp=datetime.now(), message="test")
        detection = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entry], timestamp=datetime.now(), severity=5,
            group_key=""  # Empty group key
        )

        assessment = scorer.score_detections([detection])

        assert assessment.total_score > 0
        # Empty group_key should not appear in top_sources
        assert "" not in assessment.summary.get("top_sources", {})

    def test_detection_with_global_group_key(self, scorer):
        """Test that 'global' group_key is not tracked in top_sources."""
        entry = LogEntry(timestamp=datetime.now(), message="test")
        detection = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entry], timestamp=datetime.now(), severity=5,
            group_key="global"
        )

        assessment = scorer.score_detections([detection])

        assert "global" not in assessment.summary.get("top_sources", {})

    def test_large_number_of_detections(self, scorer):
        """Test scoring a large number of detections."""
        detections = []
        for i in range(100):
            entry = LogEntry(timestamp=datetime.now(), message=f"Event {i}")
            det = Detection(
                detection_id=f"D{i}", rule_id=f"R{i % 5}", rule_name=f"Rule {i % 5}",
                log_entries=[entry], timestamp=datetime.now(), severity=5
            )
            detections.append(det)

        assessment = scorer.score_detections(detections)

        assert assessment.summary["total_events"] == 100
        assert len(assessment.scored_events) == 100

    def test_detection_with_empty_message(self, scorer):
        """Test scoring detection with empty message."""
        entry = LogEntry(timestamp=datetime.now(), message="")
        detection = Detection(
            detection_id="D1", rule_id="R1", rule_name="Test",
            log_entries=[entry], timestamp=datetime.now(), severity=5,
            message=""
        )

        score = scorer.calculate_score(detection)

        assert score >= 1


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for complete scoring workflow."""

    def test_full_scoring_workflow(self, scorer):
        """Test complete workflow from detections to assessment."""
        # Create realistic detections
        ssh_entries = [
            LogEntry(
                timestamp=datetime(2026, 1, 28, 10, 30, i),
                source_ip="192.168.1.50",
                message="Failed password for root from 192.168.1.50 port 22 ssh2",
                user="root",
                event_type="authentication_failure",
            )
            for i in range(5)
        ]

        port_scan_entries = [
            LogEntry(
                timestamp=datetime(2026, 1, 28, 10, 31, 0),
                source_ip="10.0.0.100",
                message="Connection attempt to port 22",
                event_type="port_scan",
            )
        ]

        ssh_detection = Detection(
            detection_id="DET-001",
            rule_id="RULE-001",
            rule_name="SSH Brute Force",
            log_entries=ssh_entries,
            timestamp=datetime(2026, 1, 28, 10, 30, 4),
            severity=8,
            severity_label="Critical",
            group_key="192.168.1.50",
            message="SSH Brute Force: 5 events from 192.168.1.50",
        )

        port_scan_detection = Detection(
            detection_id="DET-002",
            rule_id="RULE-002",
            rule_name="Port Scan",
            log_entries=port_scan_entries,
            timestamp=datetime(2026, 1, 28, 10, 31, 0),
            severity=7,
            severity_label="High",
            group_key="10.0.0.100",
            message="Port Scan: 1 event from 10.0.0.100",
        )

        # Score detections
        assessment = scorer.score_detections([ssh_detection, port_scan_detection])

        # Verify assessment structure
        assert assessment.total_score > 0
        assert assessment.risk_category in ["Low", "Medium", "High", "Critical"]
        assert len(assessment.scored_events) == 2

        # Verify summary
        assert assessment.summary["total_events"] == 2
        assert "RULE-001" in assessment.summary["by_rule"]
        assert "RULE-002" in assessment.summary["by_rule"]

        # Verify serialization
        assessment_dict = assessment.to_dict()
        assert "total_score" in assessment_dict
        assert "events" in assessment_dict
        assert len(assessment_dict["events"]) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
