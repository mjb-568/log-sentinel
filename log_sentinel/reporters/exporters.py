"""JSON and CSV export reporters."""

import csv
import io
import json
import sys
from pathlib import Path
from typing import List, Optional

from ..models import AnalysisResult, SecurityEvent


def _events_to_dicts(events: List[SecurityEvent]) -> List[dict]:
    return [e.to_dict() for e in events]


def export_json(result: AnalysisResult, output_path: Optional[Path] = None) -> None:
    """Write results as JSON to *output_path* or stdout."""
    payload = {
        "log_file": result.log_file,
        "log_type": result.log_type,
        "total_lines": result.total_lines,
        "event_count": len(result.events),
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "by_type": {k: len(v) for k, v in result.by_type.items()},
        },
        "events": _events_to_dicts(result.events),
    }
    text = json.dumps(payload, indent=2, default=str)
    if output_path:
        output_path.write_text(text, encoding="utf-8")
    else:
        print(text)


_CSV_FIELDS = [
    "timestamp", "event_type", "severity", "source_ip",
    "user", "description", "log_type", "line_number",
]


def export_csv(result: AnalysisResult, output_path: Optional[Path] = None) -> None:
    """Write results as CSV to *output_path* or stdout."""
    rows = _events_to_dicts(result.events)

    if output_path:
        fh = open(output_path, "w", newline="", encoding="utf-8")
        close = True
    else:
        fh = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="")
        close = False

    try:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if close:
            fh.close()
