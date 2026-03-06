"""Base parser interface."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Generator, Dict, Any


class BaseParser(ABC):
    """Abstract base for all log parsers.

    Each parser yields raw record dicts; detectors then classify them into
    SecurityEvents.  Keeping parsing and detection separate means new
    detectors can be applied without touching the parsers.
    """

    log_type: str = ""

    @abstractmethod
    def parse(self, path: Path) -> Generator[Dict[str, Any], None, None]:
        """Yield normalised record dicts from *path*."""

    @classmethod
    def sniff(cls, path: Path) -> bool:
        """Return True if *path* looks like this log format (best-effort)."""
        return False
