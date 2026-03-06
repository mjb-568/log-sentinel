"""Parser for Linux/Unix auth.log / secure log files.

Handles the standard syslog format used by most Linux distributions:
    Jan  1 00:00:00 hostname process[pid]: message
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, Optional

from .base import BaseParser

# Syslog header: month day time host process[pid]:
_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

# ISO 8601 syslog header (systemd journal export)
_ISO_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)"
    r"\s+(?P<host>\S+)\s+(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(match: re.Match) -> Optional[datetime]:
    try:
        month = _MONTH_MAP[match.group("month")]
        day = int(match.group("day"))
        h, m, s = map(int, match.group("time").split(":"))
        year = datetime.now().year
        return datetime(year, month, day, h, m, s)
    except (KeyError, ValueError):
        return None


def _parse_iso_timestamp(ts_str: str) -> Optional[datetime]:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            clean = ts_str.rstrip("Z").split("+")[0].split("-")[0] if False else ts_str
            # strip timezone suffix
            clean = re.sub(r"[+-]\d{2}:\d{2}$", "", ts_str).rstrip("Z")
            return datetime.strptime(clean[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue
    return None


class AuthLogParser(BaseParser):
    log_type = "auth_log"

    def parse(self, path: Path) -> Generator[Dict[str, Any], None, None]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip("\n")
                record = self._parse_line(line, lineno)
                if record:
                    yield record

    def _parse_line(self, line: str, lineno: int) -> Optional[Dict[str, Any]]:
        m = _SYSLOG_RE.match(line)
        if m:
            return {
                "timestamp": _parse_timestamp(m),
                "host": m.group("host"),
                "process": m.group("process").strip(),
                "pid": m.group("pid"),
                "message": m.group("message"),
                "raw": line,
                "line_number": lineno,
                "log_type": self.log_type,
            }
        m = _ISO_SYSLOG_RE.match(line)
        if m:
            return {
                "timestamp": _parse_iso_timestamp(m.group("ts")),
                "host": m.group("host"),
                "process": m.group("process").strip(),
                "pid": m.group("pid"),
                "message": m.group("message"),
                "raw": line,
                "line_number": lineno,
                "log_type": self.log_type,
            }
        return None

    @classmethod
    def sniff(cls, path: Path) -> bool:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    if i >= 20:
                        break
                    if _SYSLOG_RE.match(line.rstrip()) or _ISO_SYSLOG_RE.match(line.rstrip()):
                        return True
        except OSError:
            pass
        return False
