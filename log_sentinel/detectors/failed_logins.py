"""Detect failed logins and brute-force patterns."""

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ..models import EventType, SecurityEvent, Severity

# --- auth.log patterns ---

# SSH failed password
_SSH_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port",
    re.IGNORECASE,
)
# SSH invalid user (before auth)
_SSH_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)",
    re.IGNORECASE,
)
# PAM authentication failure
_PAM_FAIL = re.compile(
    r"pam_unix\([^)]+\): authentication failure.*?(?:user=(?P<user>\S+))?(?:.*?rhost=(?P<ip>\S+))?",
    re.IGNORECASE,
)
# Successful root login (suspicious)
_ROOT_LOGIN = re.compile(
    r"Accepted (?:password|publickey) for root from (?P<ip>[\d.a-fA-F:]+)",
    re.IGNORECASE,
)
# Generic accepted login
_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)",
    re.IGNORECASE,
)

# Windows Event IDs for failed logon
_WIN_FAILED_LOGON_IDS = {4625, 4776}
_WIN_SUCCESS_LOGON_IDS = {4624}

# Logon failure subcodes (for Windows Event 4625)
_LOGON_FAILURE_REASONS = {
    "0xC000006A": "Wrong password",
    "0xC0000064": "Unknown username",
    "0xC000006D": "Bad username or auth info",
    "0xC000006E": "Account restriction",
    "0xC000006F": "Outside allowed time",
    "0xC0000070": "Workstation restriction",
    "0xC0000071": "Expired password",
    "0xC0000072": "Disabled account",
    "0xC0000193": "Expired account",
    "0xC0000234": "Account locked",
}


class FailedLoginDetector:
    """Detect individual failed logins and brute-force bursts."""

    def __init__(self, brute_force_threshold: int = 5, window_minutes: int = 10):
        self.threshold = brute_force_threshold
        self.window = timedelta(minutes=window_minutes)
        # ip -> list of failed timestamps
        self._ip_times: Dict[str, List[datetime]] = defaultdict(list)
        # ip -> set of usernames tried
        self._ip_users: Dict[str, set] = defaultdict(set)
        # Track which IPs we've already flagged as brute-force
        self._flagged_ips: set = set()

    def detect(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        log_type = record.get("log_type", "")
        if log_type == "auth_log":
            return self._detect_auth_log(record)
        if log_type == "windows_event":
            return self._detect_windows(record)
        if log_type == "apache_access":
            return self._detect_apache(record)
        return []

    def _make_event(
        self,
        record: Dict[str, Any],
        event_type: EventType,
        severity: Severity,
        description: str,
        user: Optional[str] = None,
        source_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        return SecurityEvent(
            timestamp=record.get("timestamp"),
            event_type=event_type,
            severity=severity,
            source_ip=source_ip or record.get("source_ip"),
            user=user or record.get("user"),
            description=description,
            raw_line=record.get("raw", ""),
            log_type=record.get("log_type", ""),
            line_number=record.get("line_number", 0),
            details=details or {},
        )

    def _record_failure(
        self, ip: Optional[str], user: Optional[str], ts: Optional[datetime]
    ) -> bool:
        """Track failure; return True if brute-force threshold just crossed."""
        if not ip or not ts:
            return False
        cutoff = ts - self.window
        times = self._ip_times[ip]
        # Prune old entries
        times[:] = [t for t in times if t >= cutoff]
        times.append(ts)
        if user:
            self._ip_users[ip].add(user)
        if len(times) >= self.threshold and ip not in self._flagged_ips:
            self._flagged_ips.add(ip)
            return True
        return False

    def _detect_auth_log(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        msg = record.get("message", "")
        events: List[SecurityEvent] = []

        # Root login
        m = _ROOT_LOGIN.search(msg)
        if m:
            events.append(
                self._make_event(
                    record,
                    EventType.ROOT_LOGIN,
                    Severity.HIGH,
                    f"Root login accepted from {m.group('ip')}",
                    user="root",
                    source_ip=m.group("ip"),
                )
            )
            return events

        # SSH failed password
        m = _SSH_FAILED.search(msg)
        if m:
            ip, user = m.group("ip"), m.group("user")
            events.append(
                self._make_event(
                    record,
                    EventType.FAILED_LOGIN,
                    Severity.MEDIUM,
                    f"SSH failed password for '{user}' from {ip}",
                    user=user,
                    source_ip=ip,
                    details={"reason": "wrong_password"},
                )
            )
            if self._record_failure(ip, user, record.get("timestamp")):
                events.append(
                    self._make_event(
                        record,
                        EventType.BRUTE_FORCE,
                        Severity.CRITICAL,
                        f"Brute-force detected: {self.threshold}+ failures from {ip} "
                        f"(users: {', '.join(self._ip_users[ip])})",
                        source_ip=ip,
                        details={
                            "failure_count": len(self._ip_times[ip]),
                            "window_minutes": self.window.seconds // 60,
                            "users_tried": list(self._ip_users[ip]),
                        },
                    )
                )
            return events

        # SSH invalid user
        m = _SSH_INVALID.search(msg)
        if m:
            ip, user = m.group("ip"), m.group("user")
            events.append(
                self._make_event(
                    record,
                    EventType.FAILED_LOGIN,
                    Severity.MEDIUM,
                    f"SSH invalid user '{user}' from {ip}",
                    user=user,
                    source_ip=ip,
                    details={"reason": "invalid_user"},
                )
            )
            if self._record_failure(ip, user, record.get("timestamp")):
                events.append(
                    self._make_event(
                        record,
                        EventType.BRUTE_FORCE,
                        Severity.CRITICAL,
                        f"Brute-force detected: {self.threshold}+ failures from {ip}",
                        source_ip=ip,
                        details={
                            "failure_count": len(self._ip_times[ip]),
                            "window_minutes": self.window.seconds // 60,
                            "users_tried": list(self._ip_users[ip]),
                        },
                    )
                )
            return events

        return events

    def _detect_windows(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        event_id = record.get("event_id", 0)
        edata = record.get("event_data", {})
        events: List[SecurityEvent] = []

        if event_id in _WIN_FAILED_LOGON_IDS:
            ip = edata.get("IpAddress") or edata.get("WorkstationName")
            user = edata.get("TargetUserName") or edata.get("UserName") or "unknown"
            subcode = edata.get("SubStatus") or edata.get("Status") or ""
            reason = _LOGON_FAILURE_REASONS.get(subcode.upper(), "Authentication failure")
            logon_type = edata.get("LogonType", "")

            events.append(
                self._make_event(
                    record,
                    EventType.FAILED_LOGIN,
                    Severity.MEDIUM,
                    f"Windows failed logon for '{user}' from {ip or 'local'}: {reason}",
                    user=user,
                    source_ip=ip,
                    details={
                        "event_id": event_id,
                        "reason": reason,
                        "logon_type": logon_type,
                        "sub_status": subcode,
                    },
                )
            )
            if self._record_failure(ip, user, record.get("timestamp")):
                events.append(
                    self._make_event(
                        record,
                        EventType.BRUTE_FORCE,
                        Severity.CRITICAL,
                        f"Brute-force detected: {self.threshold}+ Windows failures from {ip}",
                        source_ip=ip,
                        details={
                            "failure_count": len(self._ip_times.get(ip or "", [])),
                            "users_tried": list(self._ip_users.get(ip or "", set())),
                        },
                    )
                )

        return events

    def _detect_apache(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        """401 responses indicate authentication failures in Apache."""
        events: List[SecurityEvent] = []
        status = record.get("status", 0)
        if status == 401:
            ip = record.get("source_ip")
            events.append(
                self._make_event(
                    record,
                    EventType.FAILED_LOGIN,
                    Severity.LOW,
                    f"HTTP 401 Unauthorized from {ip} for {record.get('path', '')}",
                    source_ip=ip,
                    details={"status": status, "path": record.get("path")},
                )
            )
            if self._record_failure(ip, None, record.get("timestamp")):
                events.append(
                    self._make_event(
                        record,
                        EventType.BRUTE_FORCE,
                        Severity.HIGH,
                        f"HTTP brute-force: {self.threshold}+ 401s from {ip}",
                        source_ip=ip,
                        details={"failure_count": len(self._ip_times.get(ip or "", []))},
                    )
                )
        return events
