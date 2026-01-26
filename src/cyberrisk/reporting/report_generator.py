"""
ReportGenerator Module - Produces reports and visualizations.

Generates summary reports, exports analysis results, and creates
visualizations for detected security events and risk assessments.

Author: CyberRisk Team
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from cyberrisk.core.risk_scorer import RiskAssessment, ScoredEvent

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates reports and visualizations for security analysis results.

    Supports multiple output formats:
    - Text summary reports
    - JSON data export
    - HTML reports (for dashboard display)

    Example:
        generator = ReportGenerator()
        report = generator.generate_summary(assessment)
        generator.export_report("report.json", assessment, format="json")
    """

    def __init__(self, template_path: Optional[str] = None):
        """
        Initialize the ReportGenerator.

        Args:
            template_path: Optional path to custom HTML template
        """
        self.template_path = template_path
        self.reports: list[dict] = []

    def generate_summary(self, assessment: RiskAssessment) -> str:
        """
        Generate a text summary report of the risk assessment.

        Args:
            assessment: RiskAssessment to summarize

        Returns:
            Formatted text summary
        """
        lines = []
        lines.append("=" * 70)
        lines.append("CYBERRISK MONITOR - SECURITY ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Overall Risk Assessment
        lines.append("-" * 70)
        lines.append("OVERALL RISK ASSESSMENT")
        lines.append("-" * 70)
        lines.append(f"Risk Level: {assessment.risk_category}")
        lines.append(f"Total Score: {assessment.total_score}")
        lines.append(f"Events Analyzed: {len(assessment.scored_events)}")
        lines.append("")

        # Severity Distribution
        lines.append("-" * 70)
        lines.append("SEVERITY DISTRIBUTION")
        lines.append("-" * 70)
        summary = assessment.summary
        by_category = summary.get("by_category", {})
        for category in ["Critical", "High", "Medium", "Low"]:
            count = by_category.get(category, 0)
            bar = "#" * min(count * 2, 40)
            lines.append(f"{category:10s}: {count:4d} {bar}")
        lines.append("")

        # Top Detections
        lines.append("-" * 70)
        lines.append("TOP DETECTIONS BY RISK SCORE")
        lines.append("-" * 70)

        sorted_events = sorted(
            assessment.scored_events,
            key=lambda e: e.final_score,
            reverse=True
        )

        for event in sorted_events[:10]:
            lines.append(
                f"  [{event.risk_category:8s}] Score: {event.final_score:3d} | "
                f"{event.detection.rule_name}"
            )
            if event.detection.group_key != "global":
                lines.append(f"             Source: {event.detection.group_key}")
        lines.append("")

        # Detection Rules Summary
        lines.append("-" * 70)
        lines.append("DETECTION RULES TRIGGERED")
        lines.append("-" * 70)
        by_rule = summary.get("by_rule", {})
        for rule_id, rule_data in sorted(
            by_rule.items(), key=lambda x: -x[1].get("score", 0)
        ):
            name = rule_data.get("name", rule_id)
            count = rule_data.get("count", 0)
            score = rule_data.get("score", 0)
            lines.append(f"  {name}: {count} events (score: {score})")
        lines.append("")

        # Top Sources
        top_sources = summary.get("top_sources", {})
        if top_sources:
            lines.append("-" * 70)
            lines.append("TOP RISK SOURCES")
            lines.append("-" * 70)
            for source, score in list(top_sources.items())[:10]:
                lines.append(f"  {source}: {score} points")
            lines.append("")

        # Recommendations
        lines.append("-" * 70)
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 70)
        recommendations = self._generate_recommendations(assessment)
        for rec in recommendations:
            lines.append(f"  * {rec}")
        lines.append("")

        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)

        report_text = "\n".join(lines)

        # Store report
        self.reports.append({
            "timestamp": datetime.now().isoformat(),
            "type": "summary",
            "content": report_text,
        })

        return report_text

    def _generate_recommendations(self, assessment: RiskAssessment) -> list[str]:
        """Generate recommendations based on assessment results."""
        recommendations = []

        summary = assessment.summary
        by_category = summary.get("by_category", {})

        # Critical findings require immediate attention
        if by_category.get("Critical", 0) > 0:
            recommendations.append(
                "URGENT: Critical security events detected. Investigate immediately."
            )

        # High volume of authentication failures
        by_rule = summary.get("by_rule", {})
        for rule_id, data in by_rule.items():
            if "brute" in rule_id.lower() or "authentication" in data.get("name", "").lower():
                if data.get("count", 0) >= 5:
                    recommendations.append(
                        "Consider implementing account lockout policies or rate limiting."
                    )
                    break

        # Port scanning detected
        for rule_id, data in by_rule.items():
            if "scan" in rule_id.lower() or "scan" in data.get("name", "").lower():
                recommendations.append(
                    "Port scanning activity detected. Review firewall rules and IDS settings."
                )
                break

        # High number of events from single source
        top_sources = summary.get("top_sources", {})
        if top_sources:
            top_source = list(top_sources.keys())[0]
            if top_sources[top_source] > 50:
                recommendations.append(
                    f"High risk activity from {top_source}. Consider blocking or monitoring this IP."
                )

        # General recommendations based on risk level
        if assessment.risk_category == "Critical":
            recommendations.append(
                "Escalate to security team for immediate investigation."
            )
        elif assessment.risk_category == "High":
            recommendations.append(
                "Schedule security review within 24 hours."
            )
        elif assessment.risk_category == "Medium":
            recommendations.append(
                "Continue monitoring and review logs regularly."
            )
        else:
            recommendations.append(
                "No immediate action required. Maintain standard monitoring."
            )

        return recommendations

    def export_report(
        self,
        output_path: str | Path,
        assessment: RiskAssessment,
        format: str = "json"
    ) -> None:
        """
        Export assessment report to a file.

        Args:
            output_path: Path for the output file
            assessment: RiskAssessment to export
            format: Output format ('json', 'txt', 'html')
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            self._export_json(output_path, assessment)
        elif format == "txt":
            self._export_text(output_path, assessment)
        elif format == "html":
            self._export_html(output_path, assessment)
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Exported report to {output_path}")

    def _export_json(self, path: Path, assessment: RiskAssessment) -> None:
        """Export assessment as JSON."""
        data = {
            "report_type": "cyberrisk_assessment",
            "generated": datetime.now().isoformat(),
            "assessment": assessment.to_dict(),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _export_text(self, path: Path, assessment: RiskAssessment) -> None:
        """Export assessment as plain text."""
        report = self.generate_summary(assessment)
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)

    def _export_html(self, path: Path, assessment: RiskAssessment) -> None:
        """Export assessment as HTML report."""
        html = self._generate_html_report(assessment)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _generate_html_report(self, assessment: RiskAssessment) -> str:
        """Generate an HTML report."""
        # Risk level colors
        level_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
        }

        risk_color = level_colors.get(assessment.risk_category, "#6c757d")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberRisk Monitor - Security Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .header .timestamp {{ opacity: 0.8; font-size: 0.9em; }}
        .risk-badge {{
            display: inline-block;
            padding: 10px 30px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 1.2em;
            background: {risk_color};
            color: white;
            margin-top: 15px;
        }}
        .card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .card h2 {{
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 15px;
            color: #1a1a2e;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .stat-box {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-box .value {{
            font-size: 2em;
            font-weight: bold;
            color: #1a1a2e;
        }}
        .stat-box .label {{ color: #666; font-size: 0.9em; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f8f9fa; }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #28a745; color: white; }}
        .recommendation {{
            padding: 10px 15px;
            margin: 5px 0;
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            border-radius: 0 5px 5px 0;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>CyberRisk Monitor</h1>
            <div class="timestamp">Security Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            <div class="risk-badge">{assessment.risk_category} Risk</div>
        </div>

        <div class="card">
            <h2>Summary Statistics</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="value">{assessment.total_score}</div>
                    <div class="label">Total Risk Score</div>
                </div>
                <div class="stat-box">
                    <div class="value">{len(assessment.scored_events)}</div>
                    <div class="label">Security Events</div>
                </div>
                <div class="stat-box">
                    <div class="value">{assessment.summary.get('by_category', {}).get('Critical', 0)}</div>
                    <div class="label">Critical Events</div>
                </div>
                <div class="stat-box">
                    <div class="value">{assessment.summary.get('by_category', {}).get('High', 0)}</div>
                    <div class="label">High Severity</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Top Detections</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Score</th>
                        <th>Rule</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
"""
        # Add top detections
        sorted_events = sorted(
            assessment.scored_events,
            key=lambda e: e.final_score,
            reverse=True
        )[:15]

        for event in sorted_events:
            severity_class = f"severity-{event.risk_category.lower()}"
            source = event.detection.group_key if event.detection.group_key != "global" else "-"
            html += f"""
                    <tr>
                        <td><span class="severity-badge {severity_class}">{event.risk_category}</span></td>
                        <td>{event.final_score}</td>
                        <td>{event.detection.rule_name}</td>
                        <td>{source}</td>
                    </tr>
"""

        html += """
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Recommendations</h2>
"""
        recommendations = self._generate_recommendations(assessment)
        for rec in recommendations:
            html += f'            <div class="recommendation">{rec}</div>\n'

        html += f"""
        </div>

        <div class="footer">
            <p>Generated by CyberRisk Monitor v0.1.0</p>
            <p>Report ID: {assessment.timestamp.strftime('%Y%m%d%H%M%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def format_output(self, data: dict, format_type: str = "text") -> str:
        """
        Format data for output display.

        Args:
            data: Data to format
            format_type: Output format ('text', 'json')

        Returns:
            Formatted string
        """
        if format_type == "json":
            return json.dumps(data, indent=2, default=str)
        else:
            # Simple text formatting
            lines = []
            for key, value in data.items():
                if isinstance(value, dict):
                    lines.append(f"{key}:")
                    for k, v in value.items():
                        lines.append(f"  {k}: {v}")
                elif isinstance(value, list):
                    lines.append(f"{key}: [{len(value)} items]")
                else:
                    lines.append(f"{key}: {value}")
            return "\n".join(lines)

    def get_statistics(self, assessment: RiskAssessment) -> dict:
        """
        Get statistical summary of the assessment.

        Args:
            assessment: RiskAssessment to analyze

        Returns:
            Dictionary of statistics
        """
        return {
            "total_score": assessment.total_score,
            "risk_level": assessment.risk_category,
            "event_count": len(assessment.scored_events),
            "summary": assessment.summary,
        }
