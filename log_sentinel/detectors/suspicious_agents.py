"""Detect suspicious user agents and malicious HTTP request patterns."""

import re
import urllib.parse
from typing import Any, Dict, List, Optional

from ..models import EventType, SecurityEvent, Severity

# Known malicious / scanner user agent strings
_MALICIOUS_UA_PATTERNS: List[tuple] = [
    # Security scanners
    (re.compile(r"sqlmap", re.IGNORECASE), "SQLMap SQL injection scanner", Severity.CRITICAL),
    (re.compile(r"nikto", re.IGNORECASE), "Nikto web vulnerability scanner", Severity.CRITICAL),
    (re.compile(r"nmap", re.IGNORECASE), "Nmap port scanner", Severity.HIGH),
    (re.compile(r"masscan", re.IGNORECASE), "Masscan port scanner", Severity.HIGH),
    (re.compile(r"ZmEu", re.IGNORECASE), "ZmEu scanner (targets PHPMyAdmin)", Severity.HIGH),
    (re.compile(r"(?:acunetix|appscan|burpsuite|burp\s+suite|nessus|openvas)", re.IGNORECASE),
     "Web vulnerability scanner", Severity.HIGH),
    (re.compile(r"w3af", re.IGNORECASE), "w3af web attack framework", Severity.HIGH),
    (re.compile(r"(?:Havij|pangolin)", re.IGNORECASE), "SQL injection tool", Severity.CRITICAL),
    # Exploit frameworks
    (re.compile(r"(?:metasploit|msfconsole|msf)", re.IGNORECASE), "Metasploit framework", Severity.CRITICAL),
    # Directory brute-force tools
    (re.compile(r"(?:dirbuster|gobuster|feroxbuster|wfuzz|ffuf)", re.IGNORECASE),
     "Directory brute-force tool", Severity.HIGH),
    (re.compile(r"(?:hydra|medusa|brutus)", re.IGNORECASE), "Password brute-force tool", Severity.CRITICAL),
    # Scrapers / bots that are commonly abused
    (re.compile(r"(?:wget|curl)/\d", re.IGNORECASE), "Command-line HTTP client (wget/curl)", Severity.LOW),
    (re.compile(r"python-requests/\d", re.IGNORECASE), "Python requests library", Severity.LOW),
    # Completely empty UA
]

# Path-based attack patterns
_PATH_PATTERNS: List[tuple] = [
    # Directory traversal
    (re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)", re.IGNORECASE),
     EventType.DIRECTORY_TRAVERSAL, "Directory traversal attempt", Severity.HIGH),
    # SQL injection in URL
    (re.compile(
        r"(?:'|%27|--|;|%3B)\s*(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE)",
        re.IGNORECASE),
     EventType.SQL_INJECTION, "SQL injection attempt in URL", Severity.CRITICAL),
    # Basic SQL injection keywords in params
    (re.compile(
        r"(?:UNION\s+(?:ALL\s+)?SELECT|SELECT\s+\*|'[^']*'\s*=\s*'[^']*'|1=1|1%3D1)",
        re.IGNORECASE),
     EventType.SQL_INJECTION, "SQL injection pattern in URL", Severity.CRITICAL),
    # XSS
    (re.compile(
        r"(?:<script|javascript:|on(?:load|error|click|mouse|focus)=|%3Cscript|%3c%73%63%72%69%70%74)",
        re.IGNORECASE),
     EventType.XSS_ATTEMPT, "XSS attempt in URL", Severity.HIGH),
    # Common scanner paths
    (re.compile(
        r"(?:/phpmyadmin|/wp-admin|/wp-login\.php|/admin\.php|/manager/html"
        r"|/solr/admin|/jenkins|/jmx-console|/.env|/etc/passwd|/proc/self/environ"
        r"|/shell\.php|/cmd\.php|/c99\.php|/r57\.php)",
        re.IGNORECASE),
     EventType.SCANNER_DETECTED, "Common attack/scanner path probed", Severity.HIGH),
]

# Referer-based anomalies
_SUSPICIOUS_REFERERS = re.compile(
    r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\bfile://|\bdata:)",
    re.IGNORECASE,
)


class SuspiciousAgentDetector:

    def detect(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        if record.get("log_type") != "apache_access":
            return []
        events: List[SecurityEvent] = []
        events.extend(self._check_user_agent(record))
        events.extend(self._check_path(record))
        return events

    def _make_event(
        self,
        record: Dict[str, Any],
        event_type: EventType,
        severity: Severity,
        description: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        return SecurityEvent(
            timestamp=record.get("timestamp"),
            event_type=event_type,
            severity=severity,
            source_ip=record.get("source_ip"),
            user=record.get("user"),
            description=description,
            raw_line=record.get("raw", ""),
            log_type=record.get("log_type", ""),
            line_number=record.get("line_number", 0),
            details=details or {},
        )

    def _check_user_agent(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        ua = record.get("user_agent") or ""
        events: List[SecurityEvent] = []

        if not ua or ua == "-":
            events.append(
                self._make_event(
                    record,
                    EventType.SUSPICIOUS_AGENT,
                    Severity.LOW,
                    f"Empty/missing User-Agent from {record.get('source_ip')} — possible script/scanner",
                    details={"user_agent": ua, "path": record.get("path")},
                )
            )
            return events

        for pattern, label, severity in _MALICIOUS_UA_PATTERNS:
            if pattern.search(ua):
                events.append(
                    self._make_event(
                        record,
                        EventType.SUSPICIOUS_AGENT,
                        severity,
                        f"{label} detected: '{ua[:120]}'",
                        details={"user_agent": ua, "matched_tool": label},
                    )
                )
                break  # One match per request is enough

        return events

    def _check_path(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        raw_path = record.get("path") or ""
        decoded = record.get("decoded_path") or urllib.parse.unquote(raw_path)
        events: List[SecurityEvent] = []

        for pattern, event_type, label, severity in _PATH_PATTERNS:
            if pattern.search(decoded) or pattern.search(raw_path):
                events.append(
                    self._make_event(
                        record,
                        event_type,
                        severity,
                        f"{label}: {decoded[:120]}",
                        details={
                            "path": raw_path,
                            "decoded_path": decoded,
                            "method": record.get("method"),
                            "status": record.get("status"),
                        },
                    )
                )
                # Don't stack multiple path alerts for the same request
                break

        return events
