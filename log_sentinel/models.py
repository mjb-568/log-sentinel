"""Core data models for log-sentinel."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def color(self) -> str:
        return {
            "low": "cyan",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }[self.value]

    @property
    def order(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class EventType(str, Enum):
    FAILED_LOGIN = "failed_login"
    BRUTE_FORCE = "brute_force"
    ROOT_LOGIN = "root_login"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUDO_COMMAND = "sudo_command"
    SUDO_FAILURE = "sudo_failure"
    SU_FAILURE = "su_failure"
    ACCOUNT_CREATED = "account_created"
    GROUP_MODIFIED = "group_modified"
    SUSPICIOUS_AGENT = "suspicious_agent"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    SCANNER_DETECTED = "scanner_detected"
    LOG_CLEARED = "log_cleared"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE_INSTALLED = "service_installed"
    SPECIAL_PRIVILEGES = "special_privileges"
    EXPLICIT_CREDENTIALS = "explicit_credentials"

    @property
    def label(self) -> str:
        return self.value.replace("_", " ").title()


@dataclass
class SecurityEvent:
    timestamp: Optional[datetime]
    event_type: EventType
    severity: Severity
    source_ip: Optional[str]
    user: Optional[str]
    description: str
    raw_line: str
    log_type: str
    line_number: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "user": self.user,
            "description": self.description,
            "log_type": self.log_type,
            "line_number": self.line_number,
            "details": self.details,
        }


@dataclass
class AnalysisResult:
    log_file: str
    log_type: str
    total_lines: int
    events: List[SecurityEvent] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def by_severity(self) -> Dict[str, List[SecurityEvent]]:
        result: Dict[str, List[SecurityEvent]] = {s.value: [] for s in Severity}
        for event in self.events:
            result[event.severity.value].append(event)
        return result

    @property
    def by_type(self) -> Dict[str, List[SecurityEvent]]:
        result: Dict[str, List[SecurityEvent]] = {}
        for event in self.events:
            result.setdefault(event.event_type.value, []).append(event)
        return result

    @property
    def critical_count(self) -> int:
        return sum(1 for e in self.events if e.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for e in self.events if e.severity == Severity.HIGH)
