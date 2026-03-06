"""Command-line interface for log-sentinel."""

import argparse
import sys
from pathlib import Path

from .engine import analyse
from .models import Severity
from .reporters import export_csv, export_json, print_report

_SEVERITY_CHOICES = [s.value for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-sentinel",
        description=(
            "Security log analyser — detects failed logins, brute-force attacks,\n"
            "privilege escalation, and suspicious HTTP requests."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  log-sentinel auth.log
  log-sentinel access.log --type apache --output json -o report.json
  log-sentinel events.xml --type windows --severity high
  log-sentinel auth.log --brute-threshold 3 --brute-window 5
        """,
    )

    p.add_argument("file", metavar="LOG_FILE", help="Path to the log file to analyse")

    p.add_argument(
        "--type", "-t",
        dest="log_type",
        choices=["auto", "auth", "apache", "windows"],
        default="auto",
        help="Log format (default: auto-detect)",
    )

    p.add_argument(
        "--output", "-f",
        dest="output_format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )

    p.add_argument(
        "-o", "--out",
        dest="output_file",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )

    p.add_argument(
        "--severity", "-s",
        dest="min_severity",
        choices=_SEVERITY_CHOICES,
        default="low",
        help="Minimum severity level to report (default: low)",
    )

    p.add_argument(
        "--brute-threshold",
        dest="brute_threshold",
        type=int,
        default=5,
        metavar="N",
        help="Failed-login count before flagging brute-force (default: 5)",
    )

    p.add_argument(
        "--brute-window",
        dest="brute_window",
        type=int,
        default=10,
        metavar="MINUTES",
        help="Time window (minutes) for brute-force detection (default: 10)",
    )

    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable rich colour output",
    )

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    log_path = Path(args.file)
    if not log_path.exists():
        print(f"error: file not found: {log_path}", file=sys.stderr)
        return 1
    if not log_path.is_file():
        print(f"error: not a regular file: {log_path}", file=sys.stderr)
        return 1

    min_severity = Severity(args.min_severity)
    log_type = None if args.log_type == "auto" else args.log_type

    try:
        result = analyse(
            path=log_path,
            log_type=log_type,
            brute_force_threshold=args.brute_threshold,
            brute_force_window=args.brute_window,
            min_severity=min_severity,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    output_path = Path(args.output_file) if args.output_file else None

    if args.output_format == "json":
        export_json(result, output_path)
    elif args.output_format == "csv":
        export_csv(result, output_path)
    else:
        if args.no_color:
            import os
            os.environ["NO_COLOR"] = "1"
        print_report(result)
        if output_path:
            # Also write JSON alongside the table view
            export_json(result, output_path)

    return 0 if result.events else 0


if __name__ == "__main__":
    sys.exit(main())
