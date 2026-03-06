"""Log format parser registry with auto-detection."""

from pathlib import Path
from typing import Optional

from .apache import ApacheAccessLogParser
from .auth_log import AuthLogParser
from .base import BaseParser
from .windows_event import WindowsEventLogParser

_PARSERS = [AuthLogParser, ApacheAccessLogParser, WindowsEventLogParser]

LOG_TYPES = {
    "auth": AuthLogParser,
    "apache": ApacheAccessLogParser,
    "windows": WindowsEventLogParser,
}


def get_parser(log_type: Optional[str], path: Path) -> BaseParser:
    """Return an instantiated parser for the given *log_type*.

    If *log_type* is ``None`` or ``'auto'``, the format is inferred by
    inspecting the first few lines of *path*.
    """
    if log_type and log_type != "auto":
        cls = LOG_TYPES.get(log_type)
        if cls is None:
            known = ", ".join(LOG_TYPES)
            raise ValueError(f"Unknown log type '{log_type}'. Known types: {known}")
        return cls()

    # Auto-detection: try each parser's sniff() heuristic
    suffix = path.suffix.lower()
    if suffix == ".xml":
        return WindowsEventLogParser()

    for cls in _PARSERS:
        if cls.sniff(path):
            return cls()

    # Default to auth_log for unknown text files
    return AuthLogParser()


__all__ = [
    "BaseParser",
    "AuthLogParser",
    "ApacheAccessLogParser",
    "WindowsEventLogParser",
    "get_parser",
    "LOG_TYPES",
]
