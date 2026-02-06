"""
Unit tests for the ReportGenerator module.

Tests text summary generation, JSON/HTML/text export, recommendations,
statistics, format_output, and edge cases.
"""

import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cyberrisk.core.log_parser import LogEntry
from cyberrisk.core.rule_engine import Detection
from cyberrisk.core.risk_scorer import RiskScorer, RiskAssessment, ScoredEvent
from cyberrisk.reporting.report_generator import ReportGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entry(message="Test event", event_type="unknown", source_ip=None, user=None):
    return LogEntry(
        timestamp=datetime(2026, 1, 26, 10, 0, 0),
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
    group_key="192.168.1.100",
    message="Test detection",
):
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


def _make_assessment(detections=None):
    """Run detections through RiskScorer to get a real RiskAssessment."""
    if detections is None:
        detections = [
            _make_detection(severity=8, rule_id="RULE-001", rule_name="Brute Force Login"),
            _make_detection(severity=6, rule_id="RULE-002", rule_name="Port Scan Detection",
                            group_key="10.0.0.50"),
        ]
    scorer = RiskScorer()
    return scorer.score_detections(detections)


# ===========================================================================
# Test class: ReportGenerator initialization
# ===========================================================================

class TestReportGeneratorInit:
    """Tests for ReportGenerator initialization."""

    def test_default_initialization(self):
        gen = ReportGenerator()
        assert gen.template_path is None
        assert gen.reports == []

    def test_custom_template_path(self):
        gen = ReportGenerator(template_path="/tmp/custom.html")
        assert gen.template_path == "/tmp/custom.html"


# ===========================================================================
# Test class: generate_summary
# ===========================================================================

class TestGenerateSummary:
    """Tests for the text summary report."""

    def test_returns_string(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_contains_header(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert "CYBERRISK MONITOR" in report
        assert "SECURITY ANALYSIS REPORT" in report

    def test_contains_risk_category(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert assessment.risk_category in report

    def test_contains_total_score(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert str(assessment.total_score) in report

    def test_contains_event_count(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert str(len(assessment.scored_events)) in report

    def test_contains_severity_distribution(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert "SEVERITY DISTRIBUTION" in report
        for category in ("Critical", "High", "Medium", "Low"):
            assert category in report

    def test_contains_top_detections(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert "TOP DETECTIONS" in report
        assert "Brute Force Login" in report

    def test_contains_detection_rules_triggered(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert "DETECTION RULES TRIGGERED" in report

    def test_contains_top_risk_sources(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert "TOP RISK SOURCES" in report
        assert "192.168.1.100" in report

    def test_contains_recommendations(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert "RECOMMENDATIONS" in report

    def test_contains_footer(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert "END OF REPORT" in report

    def test_stores_report_in_history(self):
        gen = ReportGenerator()
        assert len(gen.reports) == 0
        gen.generate_summary(_make_assessment())
        assert len(gen.reports) == 1
        assert gen.reports[0]["type"] == "summary"
        assert "content" in gen.reports[0]

    def test_multiple_reports_accumulate(self):
        gen = ReportGenerator()
        gen.generate_summary(_make_assessment())
        gen.generate_summary(_make_assessment())
        assert len(gen.reports) == 2

    def test_empty_assessment(self):
        assessment = _make_assessment(detections=[])
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert "CYBERRISK MONITOR" in report
        assert "Low" in report  # Zero score should be Low risk

    def test_source_global_not_shown(self):
        """Detections with group_key 'global' should show without source line."""
        det = _make_detection(severity=5, group_key="global")
        assessment = _make_assessment(detections=[det])
        gen = ReportGenerator()
        report = gen.generate_summary(assessment)
        assert "Source: global" not in report


# ===========================================================================
# Test class: recommendations
# ===========================================================================

class TestRecommendations:
    """Tests for the _generate_recommendations method."""

    def test_low_risk_standard_monitoring(self):
        det = _make_detection(severity=1)
        assessment = _make_assessment(detections=[det])
        gen = ReportGenerator()
        recs = gen._generate_recommendations(assessment)
        assert any("standard monitoring" in r.lower() for r in recs)

    def test_critical_risk_escalation(self):
        entries = [_make_entry() for _ in range(10)]
        detections = [_make_detection(severity=10, entries=entries) for _ in range(5)]
        assessment = _make_assessment(detections=detections)
        gen = ReportGenerator()
        recs = gen._generate_recommendations(assessment)
        if assessment.risk_category == "Critical":
            assert any("escalate" in r.lower() for r in recs)

    def test_high_risk_review(self):
        entries = [_make_entry() for _ in range(5)]
        detections = [_make_detection(severity=9, entries=entries) for _ in range(3)]
        assessment = _make_assessment(detections=detections)
        gen = ReportGenerator()
        recs = gen._generate_recommendations(assessment)
        if assessment.risk_category == "High":
            assert any("24 hours" in r for r in recs)

    def test_medium_risk_continue_monitoring(self):
        detections = [
            _make_detection(severity=5),
            _make_detection(severity=4, group_key="10.0.0.1"),
        ]
        assessment = _make_assessment(detections=detections)
        gen = ReportGenerator()
        recs = gen._generate_recommendations(assessment)
        if assessment.risk_category == "Medium":
            assert any("monitoring" in r.lower() for r in recs)

    def test_critical_events_urgent_message(self):
        """Detections producing Critical scored events trigger urgent message."""
        entries = [_make_entry() for _ in range(10)]
        det = _make_detection(severity=10, entries=entries)
        assessment = _make_assessment(detections=[det])
        gen = ReportGenerator()
        recs = gen._generate_recommendations(assessment)
        by_cat = assessment.summary.get("by_category", {})
        if by_cat.get("Critical", 0) > 0:
            assert any("urgent" in r.lower() for r in recs)

    def test_port_scan_recommendation(self):
        det = _make_detection(
            severity=7, rule_id="RULE-002", rule_name="Port Scan Detection"
        )
        assessment = _make_assessment(detections=[det])
        gen = ReportGenerator()
        recs = gen._generate_recommendations(assessment)
        assert any("scan" in r.lower() for r in recs)

    def test_empty_assessment_recommendations(self):
        assessment = _make_assessment(detections=[])
        gen = ReportGenerator()
        recs = gen._generate_recommendations(assessment)
        assert len(recs) >= 1  # At least the risk-level recommendation


# ===========================================================================
# Test class: export_report
# ===========================================================================

class TestExportReport:
    """Tests for export_report dispatch and file writing."""

    def test_export_json(self):
        assessment = _make_assessment()
        gen = ReportGenerator()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            gen.export_report(path, assessment, format="json")
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data["report_type"] == "cyberrisk_assessment"
            assert "assessment" in data
            assert data["assessment"]["total_score"] == assessment.total_score
        finally:
            os.unlink(path)

    def test_export_text(self):
        assessment = _make_assessment()
        gen = ReportGenerator()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        try:
            gen.export_report(path, assessment, format="txt")
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            assert "CYBERRISK MONITOR" in content
            assert "RISK ASSESSMENT" in content
        finally:
            os.unlink(path)

    def test_export_html(self):
        assessment = _make_assessment()
        gen = ReportGenerator()

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            gen.export_report(path, assessment, format="html")
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content
            assert "CyberRisk Monitor" in content
        finally:
            os.unlink(path)

    def test_export_unsupported_format_raises(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        with pytest.raises(ValueError, match="Unsupported format"):
            gen.export_report("/tmp/test.xyz", assessment, format="xyz")

    def test_export_creates_parent_dirs(self):
        assessment = _make_assessment()
        gen = ReportGenerator()

        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "subdir" / "report.json"
            gen.export_report(nested, assessment, format="json")
            assert nested.exists()


# ===========================================================================
# Test class: HTML report content
# ===========================================================================

class TestHTMLReport:
    """Tests for _generate_html_report content."""

    def test_html_contains_doctype(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        html = gen._generate_html_report(assessment)
        assert "<!DOCTYPE html>" in html

    def test_html_contains_risk_badge(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        html = gen._generate_html_report(assessment)
        assert f"{assessment.risk_category} Risk" in html

    def test_html_contains_total_score(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        html = gen._generate_html_report(assessment)
        assert str(assessment.total_score) in html

    def test_html_contains_event_count(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        html = gen._generate_html_report(assessment)
        assert str(len(assessment.scored_events)) in html

    def test_html_contains_detections_table(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        html = gen._generate_html_report(assessment)
        assert "<table>" in html
        assert "Brute Force Login" in html

    def test_html_contains_recommendations(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        html = gen._generate_html_report(assessment)
        assert "recommendation" in html

    def test_html_severity_badges(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        html = gen._generate_html_report(assessment)
        assert "severity-badge" in html

    def test_html_source_dash_for_global(self):
        det = _make_detection(severity=5, group_key="global")
        assessment = _make_assessment(detections=[det])
        gen = ReportGenerator()
        html = gen._generate_html_report(assessment)
        assert "<td>-</td>" in html

    def test_html_empty_assessment(self):
        assessment = _make_assessment(detections=[])
        gen = ReportGenerator()
        html = gen._generate_html_report(assessment)
        assert "<!DOCTYPE html>" in html
        assert "Low Risk" in html


# ===========================================================================
# Test class: format_output
# ===========================================================================

class TestFormatOutput:
    """Tests for the format_output utility method."""

    def test_format_output_json(self):
        gen = ReportGenerator()
        data = {"score": 42, "level": "High"}
        output = gen.format_output(data, format_type="json")
        parsed = json.loads(output)
        assert parsed["score"] == 42
        assert parsed["level"] == "High"

    def test_format_output_text(self):
        gen = ReportGenerator()
        data = {"risk_level": "Medium", "score": 35}
        output = gen.format_output(data, format_type="text")
        assert "risk_level: Medium" in output
        assert "score: 35" in output

    def test_format_output_nested_dict(self):
        gen = ReportGenerator()
        data = {"summary": {"events": 10, "score": 50}}
        output = gen.format_output(data, format_type="text")
        assert "summary:" in output
        assert "events: 10" in output

    def test_format_output_list_value(self):
        gen = ReportGenerator()
        data = {"items": [1, 2, 3]}
        output = gen.format_output(data, format_type="text")
        assert "items: [3 items]" in output

    def test_format_output_defaults_to_text(self):
        gen = ReportGenerator()
        data = {"key": "value"}
        output = gen.format_output(data)
        assert "key: value" in output


# ===========================================================================
# Test class: get_statistics
# ===========================================================================

class TestGetStatistics:
    """Tests for the get_statistics method."""

    def test_returns_dict(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        stats = gen.get_statistics(assessment)
        assert isinstance(stats, dict)

    def test_total_score(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        stats = gen.get_statistics(assessment)
        assert stats["total_score"] == assessment.total_score

    def test_risk_level(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        stats = gen.get_statistics(assessment)
        assert stats["risk_level"] == assessment.risk_category

    def test_event_count(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        stats = gen.get_statistics(assessment)
        assert stats["event_count"] == len(assessment.scored_events)

    def test_includes_summary(self):
        assessment = _make_assessment()
        gen = ReportGenerator()
        stats = gen.get_statistics(assessment)
        assert "summary" in stats
        assert isinstance(stats["summary"], dict)

    def test_empty_assessment_stats(self):
        assessment = _make_assessment(detections=[])
        gen = ReportGenerator()
        stats = gen.get_statistics(assessment)
        assert stats["total_score"] == 0
        assert stats["risk_level"] == "Low"
        assert stats["event_count"] == 0


# ===========================================================================
# Test class: JSON export structure
# ===========================================================================

class TestJSONExportStructure:
    """Tests for the structure and content of JSON exports."""

    def test_json_has_report_type(self):
        assessment = _make_assessment()
        gen = ReportGenerator()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            gen.export_report(path, assessment, format="json")
            with open(path, "r") as f:
                data = json.load(f)
            assert data["report_type"] == "cyberrisk_assessment"
        finally:
            os.unlink(path)

    def test_json_has_generated_timestamp(self):
        assessment = _make_assessment()
        gen = ReportGenerator()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            gen.export_report(path, assessment, format="json")
            with open(path, "r") as f:
                data = json.load(f)
            assert "generated" in data
        finally:
            os.unlink(path)

    def test_json_assessment_has_events(self):
        assessment = _make_assessment()
        gen = ReportGenerator()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            gen.export_report(path, assessment, format="json")
            with open(path, "r") as f:
                data = json.load(f)
            assert "events" in data["assessment"]
            assert len(data["assessment"]["events"]) == len(assessment.scored_events)
        finally:
            os.unlink(path)

    def test_json_valid_structure(self):
        assessment = _make_assessment()
        gen = ReportGenerator()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            gen.export_report(path, assessment, format="json")
            with open(path, "r") as f:
                data = json.load(f)
            a = data["assessment"]
            assert "total_score" in a
            assert "risk_category" in a
            assert "risk_level" in a
            assert "event_count" in a
        finally:
            os.unlink(path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
