"""
Integration tests for the CyberRisk Monitor pipeline.

Tests the full data flow: LogParser -> RuleEngine -> RiskScorer -> ReportGenerator.
Verifies format compatibility between modules and end-to-end analysis using
the sample log files in data/sample_logs/.
"""

import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cyberrisk.core.log_parser import LogParser, LogEntry
from cyberrisk.core.rule_engine import RuleEngine, Rule, Detection
from cyberrisk.core.risk_scorer import RiskScorer, RiskAssessment, ScoredEvent
from cyberrisk.reporting.report_generator import ReportGenerator

# Path helpers
PROJECT_ROOT = Path(__file__).parent.parent
SAMPLE_LOGS_DIR = PROJECT_ROOT / "data" / "sample_logs"
RULES_CONFIG = PROJECT_ROOT / "config" / "rules.json"


# ===========================================================================
# Test class: LogParser -> RuleEngine data flow
# ===========================================================================

class TestParserToEngine:
    """Tests that LogParser output is compatible with RuleEngine input."""

    def test_parsed_entries_are_logentry_instances(self):
        """LogParser produces LogEntry objects accepted by RuleEngine."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_syslog.log")

        assert len(entries) > 0
        for entry in entries:
            assert isinstance(entry, LogEntry)
            assert isinstance(entry.timestamp, datetime)

    def test_engine_accepts_parsed_syslog(self):
        """RuleEngine.evaluate_logs() accepts entries from syslog parsing."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_syslog.log")

        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)

        detections = engine.evaluate_logs(entries)
        assert isinstance(detections, list)
        for det in detections:
            assert isinstance(det, Detection)

    def test_engine_accepts_parsed_json(self):
        """RuleEngine.evaluate_logs() accepts entries from JSON parsing."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_json.log")

        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)

        detections = engine.evaluate_logs(entries)
        assert isinstance(detections, list)

    def test_engine_accepts_parsed_csv(self):
        """RuleEngine.evaluate_logs() accepts entries from CSV parsing."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_data.csv")

        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)

        detections = engine.evaluate_logs(entries)
        assert isinstance(detections, list)

    def test_detection_references_original_entries(self):
        """Each Detection contains references to the LogEntry objects that triggered it."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_syslog.log")

        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)
        detections = engine.evaluate_logs(entries)

        for det in detections:
            assert len(det.log_entries) > 0
            for entry in det.log_entries:
                assert isinstance(entry, LogEntry)
                assert entry.message != ""


# ===========================================================================
# Test class: RuleEngine -> RiskScorer data flow
# ===========================================================================

class TestEngineToScorer:
    """Tests that RuleEngine output is compatible with RiskScorer input."""

    def _get_detections(self):
        """Helper: parse syslog and run rule engine to get detections."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_syslog.log")
        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)
        return engine.evaluate_logs(entries)

    def test_scorer_accepts_detections(self):
        """RiskScorer.score_detections() accepts Detection objects from RuleEngine."""
        detections = self._get_detections()
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        assert isinstance(assessment, RiskAssessment)

    def test_scored_events_match_detection_count(self):
        """Number of scored events equals number of input detections."""
        detections = self._get_detections()
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        assert len(assessment.scored_events) == len(detections)

    def test_scored_events_have_valid_scores(self):
        """All scored events have positive integer scores."""
        detections = self._get_detections()
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        for event in assessment.scored_events:
            assert isinstance(event.final_score, int)
            assert event.final_score >= 1

    def test_scored_events_have_valid_categories(self):
        """All scored events have valid risk category labels."""
        detections = self._get_detections()
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        valid_categories = {"Low", "Medium", "High", "Critical"}
        for event in assessment.scored_events:
            assert event.risk_category in valid_categories


# ===========================================================================
# Test class: RiskScorer -> ReportGenerator data flow
# ===========================================================================

class TestScorerToReport:
    """Tests that RiskScorer output is compatible with ReportGenerator input."""

    def _get_assessment(self):
        """Helper: run full pipeline up to RiskScorer."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_syslog.log")
        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)
        detections = engine.evaluate_logs(entries)
        scorer = RiskScorer()
        return scorer.score_detections(detections)

    def test_report_generator_accepts_assessment(self):
        """ReportGenerator.generate_summary() accepts a RiskAssessment."""
        assessment = self._get_assessment()
        generator = ReportGenerator()
        report = generator.generate_summary(assessment)

        assert isinstance(report, str)
        assert len(report) > 0

    def test_summary_report_contains_risk_level(self):
        """Text summary report includes the risk category."""
        assessment = self._get_assessment()
        generator = ReportGenerator()
        report = generator.generate_summary(assessment)

        assert assessment.risk_category in report

    def test_summary_report_contains_total_score(self):
        """Text summary report includes the total score."""
        assessment = self._get_assessment()
        generator = ReportGenerator()
        report = generator.generate_summary(assessment)

        assert str(assessment.total_score) in report

    def test_json_export(self):
        """ReportGenerator exports valid JSON with assessment data."""
        assessment = self._get_assessment()
        generator = ReportGenerator()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            output_path = f.name

        try:
            generator.export_report(output_path, assessment, format="json")

            with open(output_path, "r") as f:
                data = json.load(f)

            assert "report_type" in data
            assert data["report_type"] == "cyberrisk_assessment"
            assert "assessment" in data
            assert data["assessment"]["total_score"] == assessment.total_score
        finally:
            os.unlink(output_path)

    def test_text_export(self):
        """ReportGenerator exports a text report file."""
        assessment = self._get_assessment()
        generator = ReportGenerator()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            output_path = f.name

        try:
            generator.export_report(output_path, assessment, format="txt")

            with open(output_path, "r") as f:
                content = f.read()

            assert "CYBERRISK MONITOR" in content
            assert "RISK ASSESSMENT" in content
        finally:
            os.unlink(output_path)

    def test_html_export(self):
        """ReportGenerator exports an HTML report file."""
        assessment = self._get_assessment()
        generator = ReportGenerator()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".html", delete=False
        ) as f:
            output_path = f.name

        try:
            generator.export_report(output_path, assessment, format="html")

            with open(output_path, "r") as f:
                content = f.read()

            assert "<!DOCTYPE html>" in content
            assert "CyberRisk Monitor" in content
            assert assessment.risk_category in content
        finally:
            os.unlink(output_path)

    def test_get_statistics(self):
        """ReportGenerator.get_statistics() returns a valid summary dict."""
        assessment = self._get_assessment()
        generator = ReportGenerator()
        stats = generator.get_statistics(assessment)

        assert stats["total_score"] == assessment.total_score
        assert stats["risk_level"] == assessment.risk_category
        assert stats["event_count"] == len(assessment.scored_events)

    def test_format_output_json(self):
        """ReportGenerator.format_output() produces valid JSON string."""
        assessment = self._get_assessment()
        generator = ReportGenerator()

        data = assessment.to_dict()
        output = generator.format_output(data, format_type="json")

        parsed = json.loads(output)
        assert parsed["total_score"] == assessment.total_score

    def test_format_output_text(self):
        """ReportGenerator.format_output() produces readable text."""
        generator = ReportGenerator()
        data = {"risk_level": "High", "score": 60}
        output = generator.format_output(data, format_type="text")

        assert "risk_level: High" in output
        assert "score: 60" in output


# ===========================================================================
# Test class: Full end-to-end pipeline
# ===========================================================================

class TestEndToEndPipeline:
    """Tests the complete pipeline from raw log files to final report."""

    def _run_pipeline(self, log_file):
        """Run the full analysis pipeline on a single log file."""
        parser = LogParser()
        entries = parser.parse_file(log_file)

        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)
        detections = engine.evaluate_logs(entries)

        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        generator = ReportGenerator()
        report = generator.generate_summary(assessment)

        return entries, detections, assessment, report

    def test_syslog_end_to_end(self):
        """Full pipeline processes sample_syslog.log without errors."""
        entries, detections, assessment, report = self._run_pipeline(
            SAMPLE_LOGS_DIR / "sample_syslog.log"
        )

        assert len(entries) > 0
        assert isinstance(assessment, RiskAssessment)
        assert isinstance(report, str)
        assert len(report) > 0

    def test_json_end_to_end(self):
        """Full pipeline processes sample_json.log without errors."""
        entries, detections, assessment, report = self._run_pipeline(
            SAMPLE_LOGS_DIR / "sample_json.log"
        )

        assert len(entries) > 0
        assert isinstance(assessment, RiskAssessment)

    def test_csv_end_to_end(self):
        """Full pipeline processes sample_data.csv without errors."""
        entries, detections, assessment, report = self._run_pipeline(
            SAMPLE_LOGS_DIR / "sample_data.csv"
        )

        assert len(entries) > 0
        assert isinstance(assessment, RiskAssessment)

    def test_syslog_detects_brute_force(self):
        """Syslog sample contains repeated failed logins that trigger detection."""
        entries, detections, assessment, _ = self._run_pipeline(
            SAMPLE_LOGS_DIR / "sample_syslog.log"
        )

        # The syslog has 6 failed password lines for admin from 192.168.1.105
        # plus 3 from 203.0.113.50 – should trigger brute force rules
        assert len(detections) > 0

        rule_ids = {d.rule_id for d in detections}
        rule_names = {d.rule_name for d in detections}
        # Should have at least one detection related to failed authentication
        has_auth_detection = any(
            "fail" in name.lower()
            or "brute" in name.lower()
            or "auth" in name.lower()
            or "ssh" in name.lower()
            for name in rule_names
        )
        assert has_auth_detection, (
            f"Expected an authentication-related detection. Got rules: {rule_names}"
        )

    def test_syslog_risk_is_nontrivial(self):
        """Syslog sample should produce a risk score above zero."""
        _, _, assessment, _ = self._run_pipeline(
            SAMPLE_LOGS_DIR / "sample_syslog.log"
        )
        assert assessment.total_score > 0

    def test_json_detects_threats(self):
        """JSON sample contains malware and escalation events that trigger rules."""
        _, detections, assessment, _ = self._run_pipeline(
            SAMPLE_LOGS_DIR / "sample_json.log"
        )

        # JSON log contains: privilege_escalation, malware, firewall modification
        assert len(detections) > 0
        assert assessment.total_score > 0

    def test_csv_detects_threats(self):
        """CSV sample contains authentication failures and escalation events."""
        _, detections, assessment, _ = self._run_pipeline(
            SAMPLE_LOGS_DIR / "sample_data.csv"
        )

        assert len(detections) > 0
        assert assessment.total_score > 0

    def test_report_reflects_detections(self):
        """Report content reflects the number of detections analyzed."""
        entries, detections, assessment, report = self._run_pipeline(
            SAMPLE_LOGS_DIR / "sample_syslog.log"
        )

        assert str(len(assessment.scored_events)) in report

    def test_pipeline_with_all_sample_files(self):
        """Run pipeline on each sample file and verify consistent structure."""
        sample_files = [
            SAMPLE_LOGS_DIR / "sample_syslog.log",
            SAMPLE_LOGS_DIR / "sample_json.log",
            SAMPLE_LOGS_DIR / "sample_data.csv",
        ]

        for log_file in sample_files:
            entries, detections, assessment, report = self._run_pipeline(log_file)

            # Structural checks
            assert isinstance(entries, list), f"Failed for {log_file.name}"
            assert isinstance(detections, list), f"Failed for {log_file.name}"
            assert isinstance(assessment, RiskAssessment), f"Failed for {log_file.name}"
            assert isinstance(report, str), f"Failed for {log_file.name}"

            # Assessment should have valid structure
            data = assessment.to_dict()
            assert "total_score" in data
            assert "risk_category" in data
            assert "events" in data

    def test_assessment_serialization_roundtrip(self):
        """RiskAssessment can be serialized to JSON and key fields verified."""
        _, _, assessment, _ = self._run_pipeline(
            SAMPLE_LOGS_DIR / "sample_syslog.log"
        )

        data = assessment.to_dict()
        json_str = json.dumps(data, default=str)
        parsed = json.loads(json_str)

        assert parsed["total_score"] == assessment.total_score
        assert parsed["risk_category"] == assessment.risk_category
        assert parsed["event_count"] == len(assessment.scored_events)


# ===========================================================================
# Test class: Multi-format consistency
# ===========================================================================

class TestMultiFormatConsistency:
    """Tests that the pipeline produces consistent structures across log formats."""

    def test_assessment_structure_consistent_across_formats(self):
        """All log formats produce assessments with the same field structure."""
        parser = LogParser()
        engine = RuleEngine()
        scorer = RiskScorer()

        expected_keys = {"total_score", "risk_level", "risk_category",
                         "timestamp", "summary", "event_count", "events"}

        for log_file in SAMPLE_LOGS_DIR.iterdir():
            if not log_file.is_file():
                continue

            entries = parser.parse_file(log_file)
            engine_copy = RuleEngine()
            engine_copy.load_rules(RULES_CONFIG)
            detections = engine_copy.evaluate_logs(entries)
            assessment = scorer.score_detections(detections)

            data = assessment.to_dict()
            assert expected_keys.issubset(data.keys()), (
                f"Missing keys in {log_file.name}: "
                f"{expected_keys - data.keys()}"
            )

    def test_report_generator_handles_all_formats(self):
        """ReportGenerator produces non-empty reports for all log formats."""
        parser = LogParser()
        scorer = RiskScorer()
        generator = ReportGenerator()

        for log_file in SAMPLE_LOGS_DIR.iterdir():
            if not log_file.is_file():
                continue

            entries = parser.parse_file(log_file)
            engine = RuleEngine()
            engine.load_rules(RULES_CONFIG)
            detections = engine.evaluate_logs(entries)
            assessment = scorer.score_detections(detections)
            report = generator.generate_summary(assessment)

            assert len(report) > 100, (
                f"Report too short for {log_file.name}: {len(report)} chars"
            )


# ===========================================================================
# Test class: Edge cases in integration
# ===========================================================================

class TestIntegrationEdgeCases:
    """Integration-level edge case tests."""

    def test_empty_log_file(self):
        """Pipeline handles an empty log file gracefully."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as f:
            f.write("")
            temp_path = f.name

        try:
            parser = LogParser()
            entries = parser.parse_file(temp_path)

            engine = RuleEngine()
            engine.load_rules(RULES_CONFIG)
            detections = engine.evaluate_logs(entries)

            scorer = RiskScorer()
            assessment = scorer.score_detections(detections)

            generator = ReportGenerator()
            report = generator.generate_summary(assessment)

            assert len(entries) == 0
            assert len(detections) == 0
            assert assessment.total_score == 0
            assert assessment.risk_category == "Low"
            assert isinstance(report, str)
        finally:
            os.unlink(temp_path)

    def test_no_rules_loaded(self):
        """Pipeline produces zero detections when no rules are loaded."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_syslog.log")

        engine = RuleEngine()  # No rules loaded
        detections = engine.evaluate_logs(entries)

        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        assert len(entries) > 0
        assert len(detections) == 0
        assert assessment.total_score == 0

    def test_all_rules_disabled(self):
        """Pipeline produces zero detections when all rules are disabled."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_syslog.log")

        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)
        for rule in engine.get_rules():
            rule.disable()

        detections = engine.evaluate_logs(entries)
        assert len(detections) == 0

    def test_parse_directory_feeds_pipeline(self):
        """LogParser.parse_directory() output works with the full pipeline."""
        parser = LogParser()
        entries = parser.parse_directory(SAMPLE_LOGS_DIR, pattern="*")

        assert len(entries) > 0

        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)
        detections = engine.evaluate_logs(entries)

        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)

        generator = ReportGenerator()
        report = generator.generate_summary(assessment)

        assert assessment.total_score > 0
        assert len(report) > 100

    def test_export_unsupported_format_raises(self):
        """Exporting with an unsupported format raises ValueError."""
        parser = LogParser()
        entries = parser.parse_file(SAMPLE_LOGS_DIR / "sample_syslog.log")
        engine = RuleEngine()
        engine.load_rules(RULES_CONFIG)
        detections = engine.evaluate_logs(entries)
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)
        generator = ReportGenerator()

        with pytest.raises(ValueError, match="Unsupported format"):
            generator.export_report("/tmp/test.xyz", assessment, format="xyz")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
