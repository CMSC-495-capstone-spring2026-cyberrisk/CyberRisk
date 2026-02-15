"""
CyberRisk Monitor - Command Line Interface

Provides a command-line interface for analyzing log files and generating
security risk assessments.

Usage:
    python -m cyberrisk.cli analyze <log_file> [options]
    python -m cyberrisk.cli --help

Author: CyberRisk Team
"""

import argparse
import logging
import sys
from pathlib import Path

from cyberrisk.core.log_parser import LogParser
from cyberrisk.core.rule_engine import RuleEngine
from cyberrisk.core.risk_scorer import RiskScorer
from cyberrisk.reporting.report_generator import ReportGenerator
from cyberrisk.storage import save_run  # persistence layer


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def get_default_rules_path() -> Path:
    """Get the default path to the rules configuration file."""
    # Try relative to package
    package_dir = Path(__file__).parent.parent.parent
    rules_path = package_dir / "config" / "rules.json"

    if rules_path.exists():
        return rules_path

    # Try current working directory
    cwd_rules = Path.cwd() / "config" / "rules.json"
    if cwd_rules.exists():
        return cwd_rules

    return rules_path


def _serialize_detections(detections) -> list:
    """
    Convert detections to JSON-friendly objects.

    Tries Detection.to_dict() if available; otherwise falls back to str().
    """
    out = []
    for d in detections:
        if hasattr(d, "to_dict") and callable(getattr(d, "to_dict")):
            try:
                out.append(d.to_dict())
                continue
            except Exception:
                pass
        out.append(str(d))
    return out


def analyze_logs(args: argparse.Namespace) -> int:
    """
    Analyze log files and generate risk assessment.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # Validate input file
    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Error: Log file not found: {log_path}", file=sys.stderr)
        return 1

    # Get rules path
    rules_path = Path(args.rules) if args.rules else get_default_rules_path()
    if not rules_path.exists():
        print(f"Error: Rules file not found: {rules_path}", file=sys.stderr)
        return 1

    print(f"\n{'='*60}")
    print("CYBERRISK MONITOR - Security Log Analysis")
    print(f"{'='*60}")
    print(f"Log file: {log_path}")
    print(f"Rules:    {rules_path}")
    print()

    try:
        # Step 1: Parse logs
        print("[1/4] Parsing log file...")
        parser = LogParser()
        entries = parser.parse_file(log_path)
        print(f"      Parsed {len(entries)} log entries")

        if parser.errors:
            print(f"      Warning: {len(parser.errors)} parsing errors")
            if args.verbose:
                for error in parser.errors[:5]:
                    print(f"        - {error}")

        if not entries:
            print("      No log entries found. Check file format.")
            return 1

        # Step 2: Load rules and evaluate
        print("[2/4] Loading detection rules...")
        engine = RuleEngine()
        num_rules = engine.load_rules(rules_path)
        print(f"      Loaded {num_rules} detection rules")

        print("[3/4] Evaluating logs against rules...")
        detections = engine.evaluate_logs(entries)
        print(f"      Generated {len(detections)} detections")

        # Step 3: Score risks
        print("[4/4] Calculating risk scores...")
        scorer = RiskScorer()
        assessment = scorer.score_detections(detections)
        print(f"      Total risk score: {assessment.total_score}")
        print()

        # Generate and display report
        generator = ReportGenerator()
        report = generator.generate_summary(assessment)
        print(report)

        # --- Persist run results (backend persistence) ---
        # Save a stable JSON payload so the UI can load the latest run.
        try:
            # Build a map from detection_id -> scored risk_category so the
            # UI displays the same severity labels as the CLI report.
            scored_category_map = {}
            for se in assessment.scored_events:
                scored_category_map[se.detection.detection_id] = se.risk_category

            serialized = _serialize_detections(detections)
            for det in serialized:
                if isinstance(det, dict) and det.get("detection_id") in scored_category_map:
                    det["severity_label"] = scored_category_map[det["detection_id"]]

            payload = {
                "input_path": str(log_path),
                "rules_path": str(rules_path),
                "parsed_entries": len(entries),
                "rules_loaded": int(num_rules),
                "detections_count": len(detections),
                "summary": {
                    "risk_level": str(getattr(assessment, "risk_category", "Unknown")),
                    "total_score": int(getattr(assessment, "total_score", 0)),
                },
                "detections": serialized,
            }

            saved_path = save_run(payload)
            print(f"\nSaved run results to: {saved_path}")
            print("Latest run pointer updated: data/runs/latest.json")

        except Exception as e:
            # Don't fail the analysis if saving fails; just warn.
            logger.warning("Could not save run results: %s", e)

        # Export report if requested
        if args.output:
            output_path = Path(args.output)
            output_format = args.format or output_path.suffix.lstrip(".") or "json"
            generator.export_report(output_path, assessment, format=output_format)
            print(f"\nReport exported to: {output_path}")

        # Return appropriate exit code based on risk level
        if getattr(assessment, "risk_category", "") == "Critical":
            return 2
        elif getattr(assessment, "risk_category", "") == "High":
            return 1
        return 0

    except Exception as e:
        logger.exception("Analysis failed")
        print(f"\nError: {e}", file=sys.stderr)
        return 1


def list_rules(args: argparse.Namespace) -> int:
    """List all available detection rules."""
    rules_path = Path(args.rules) if args.rules else get_default_rules_path()

    if not rules_path.exists():
        print(f"Error: Rules file not found: {rules_path}", file=sys.stderr)
        return 1

    engine = RuleEngine()
    engine.load_rules(rules_path)

    print(f"\n{'='*60}")
    print("AVAILABLE DETECTION RULES")
    print(f"{'='*60}\n")

    for rule in sorted(engine.get_rules(), key=lambda r: r.rule_id):
        status = "ENABLED" if rule.enabled else "DISABLED"
        print(f"[{rule.rule_id}] {rule.name}")
        print(f"    Severity: {rule.severity}/10 | Threshold: {rule.threshold} | Status: {status}")
        print(f"    {rule.description}")
        print()

    print(f"Total: {len(engine.get_rules())} rules ({len(engine.get_enabled_rules())} enabled)")
    return 0


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="cyberrisk",
        description="CyberRisk Monitor - A lightweight cybersecurity monitoring tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cyberrisk analyze security.log
  cyberrisk analyze logs/auth.json -o report.html -f html
  cyberrisk analyze data.csv --rules custom_rules.json -v
  cyberrisk list-rules
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze log files for security risks",
    )
    analyze_parser.add_argument(
        "log_file",
        help="Path to the log file to analyze",
    )
    analyze_parser.add_argument(
        "-r", "--rules",
        help="Path to custom rules configuration file",
    )
    analyze_parser.add_argument(
        "-o", "--output",
        help="Path for output report file",
    )
    analyze_parser.add_argument(
        "-f", "--format",
        choices=["json", "txt", "html"],
        help="Output format (default: based on file extension)",
    )
    analyze_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    analyze_parser.set_defaults(func=analyze_logs)

    # List rules command
    list_parser = subparsers.add_parser(
        "list-rules",
        help="List available detection rules",
    )
    list_parser.add_argument(
        "-r", "--rules",
        help="Path to rules configuration file",
    )
    list_parser.set_defaults(func=list_rules)

    return parser


def main() -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
