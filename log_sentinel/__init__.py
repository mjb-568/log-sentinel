"""log-sentinel: security log analysis CLI."""

__version__ = "1.0.0"
__author__ = "log-sentinel"

from .engine import analyse
from .models import AnalysisResult, EventType, SecurityEvent, Severity

__all__ = ["analyse", "AnalysisResult", "SecurityEvent", "EventType", "Severity"]
