"""Analysis engine: wires parsers → detectors → result."""

from pathlib import Path
from typing import Optional

from .detectors import DetectorPipeline
from .models import AnalysisResult, Severity
from .parsers import get_parser


def analyse(
    path: Path,
    log_type: Optional[str] = None,
    brute_force_threshold: int = 5,
    brute_force_window: int = 10,
    min_severity: Severity = Severity.LOW,
) -> AnalysisResult:
    """Parse *path* and run all detectors.  Returns an :class:`AnalysisResult`."""
    parser = get_parser(log_type, path)
    pipeline = DetectorPipeline(
        brute_force_threshold=brute_force_threshold,
        brute_force_window=brute_force_window,
        min_severity=min_severity,
    )

    result = AnalysisResult(
        log_file=str(path),
        log_type=parser.log_type,
        total_lines=0,
    )

    for record in parser.parse(path):
        result.total_lines += 1
        for event in pipeline.process(record):
            result.events.append(event)

    return result
