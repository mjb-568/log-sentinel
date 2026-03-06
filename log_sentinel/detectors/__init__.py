"""Security detector pipeline."""

from typing import Any, Dict, List

from ..models import SecurityEvent, Severity
from .failed_logins import FailedLoginDetector
from .privilege_escalation import PrivilegeEscalationDetector
from .suspicious_agents import SuspiciousAgentDetector


class DetectorPipeline:
    """Runs all detectors against each parsed log record."""

    def __init__(
        self,
        brute_force_threshold: int = 5,
        brute_force_window: int = 10,
        min_severity: Severity = Severity.LOW,
    ):
        self.min_severity = min_severity
        self._detectors = [
            FailedLoginDetector(
                brute_force_threshold=brute_force_threshold,
                window_minutes=brute_force_window,
            ),
            PrivilegeEscalationDetector(),
            SuspiciousAgentDetector(),
        ]

    def process(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        """Return all SecurityEvents emitted for a single parsed record."""
        events: List[SecurityEvent] = []
        for detector in self._detectors:
            for event in detector.detect(record):
                if event.severity.order >= self.min_severity.order:
                    events.append(event)
        return events


__all__ = ["DetectorPipeline", "FailedLoginDetector", "PrivilegeEscalationDetector", "SuspiciousAgentDetector"]
