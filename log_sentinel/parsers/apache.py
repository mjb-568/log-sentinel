"""Parser for Apache / Nginx Combined Log Format.

Standard combined log format:
    host ident authuser [day/month/year:hour:min:sec zone] "request" status size "referer" "ua"

Also handles the common variant without referer/UA (Common Log Format).
"""

import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, Optional

from .base import BaseParser

# Combined / Common log format
_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+'          # client IP
    r'\S+\s+'                    # ident (usually -)
    r'(?P<user>\S+)\s+'         # auth user
    r'\[(?P<time>[^\]]+)\]\s+'  # time
    r'"(?P<request>[^"]*)"\s+'  # request line
    r'(?P<status>\d{3})\s+'     # status code
    r'(?P<size>\S+)'             # response size
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'  # optional referer + UA
)

_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_time(raw: str) -> Optional[datetime]:
    try:
        return datetime.strptime(raw, _TIME_FMT)
    except ValueError:
        return None


def _parse_request(request_str: str) -> Dict[str, Optional[str]]:
    parts = request_str.split(" ", 2)
    method = parts[0] if len(parts) > 0 else None
    path = parts[1] if len(parts) > 1 else None
    protocol = parts[2] if len(parts) > 2 else None
    return {"method": method, "path": path, "protocol": protocol}


class ApacheAccessLogParser(BaseParser):
    log_type = "apache_access"

    def parse(self, path: Path) -> Generator[Dict[str, Any], None, None]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip("\n")
                record = self._parse_line(line, lineno)
                if record:
                    yield record

    def _parse_line(self, line: str, lineno: int) -> Optional[Dict[str, Any]]:
        m = _COMBINED_RE.match(line)
        if not m:
            return None

        req = _parse_request(m.group("request"))
        raw_path = req.get("path") or ""
        decoded_path = urllib.parse.unquote(raw_path)

        size_str = m.group("size")
        size = int(size_str) if size_str and size_str.isdigit() else 0

        return {
            "timestamp": _parse_time(m.group("time")),
            "source_ip": m.group("ip"),
            "user": m.group("user") if m.group("user") != "-" else None,
            "method": req["method"],
            "path": raw_path,
            "decoded_path": decoded_path,
            "protocol": req["protocol"],
            "status": int(m.group("status")),
            "size": size,
            "referer": m.group("referer"),
            "user_agent": m.group("ua"),
            "raw": line,
            "line_number": lineno,
            "log_type": self.log_type,
        }

    @classmethod
    def sniff(cls, path: Path) -> bool:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    if i >= 20:
                        break
                    if _COMBINED_RE.match(line.rstrip()):
                        return True
        except OSError:
            pass
        return False
