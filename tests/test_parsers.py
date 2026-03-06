"""Tests for parsers and detectors using fixture log files."""

import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"

# Allow running without install
sys.path.insert(0, str(Path(__file__).parent.parent))

from log_sentinel.engine import analyse
from log_sentinel.models import EventType, Severity


# ── auth.log ──────────────────────────────────────────────────────────────────

class TestAuthLog:
    def setup_method(self):
        self.result = analyse(FIXTURES / "auth.log")

    def test_log_type_detected(self):
        assert self.result.log_type == "auth_log"

    def test_lines_parsed(self):
        assert self.result.total_lines >= 10

    def test_failed_logins_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.FAILED_LOGIN in types

    def test_brute_force_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.BRUTE_FORCE in types

    def test_brute_force_from_correct_ip(self):
        bf = [e for e in self.result.events if e.event_type == EventType.BRUTE_FORCE]
        assert any(e.source_ip == "192.168.1.50" for e in bf)

    def test_root_login_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.ROOT_LOGIN in types

    def test_root_login_severity(self):
        root_events = [e for e in self.result.events if e.event_type == EventType.ROOT_LOGIN]
        assert all(e.severity in (Severity.HIGH, Severity.CRITICAL) for e in root_events)

    def test_sudo_command_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.SUDO_COMMAND in types

    def test_sudo_failure_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.SUDO_FAILURE in types

    def test_account_created_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.ACCOUNT_CREATED in types

    def test_group_modified_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.GROUP_MODIFIED in types

    def test_sudo_to_group_sudo_is_high(self):
        group_events = [e for e in self.result.events if e.event_type == EventType.GROUP_MODIFIED]
        sudo_add = [e for e in group_events if e.details.get("group", "").lower() == "sudo"]
        assert all(e.severity in (Severity.HIGH, Severity.CRITICAL) for e in sudo_add)


# ── Apache access log ─────────────────────────────────────────────────────────

class TestApacheLog:
    def setup_method(self):
        self.result = analyse(FIXTURES / "access.log")

    def test_log_type_detected(self):
        assert self.result.log_type == "apache_access"

    def test_sqlmap_detected(self):
        agent_events = [e for e in self.result.events if e.event_type == EventType.SUSPICIOUS_AGENT]
        assert any("sqlmap" in e.details.get("user_agent", "").lower() for e in agent_events)

    def test_sqlmap_is_critical(self):
        agent_events = [e for e in self.result.events if e.event_type == EventType.SUSPICIOUS_AGENT]
        sqlmap = [e for e in agent_events if "sqlmap" in e.details.get("user_agent", "").lower()]
        assert all(e.severity == Severity.CRITICAL for e in sqlmap)

    def test_nikto_detected(self):
        agent_events = [e for e in self.result.events if e.event_type == EventType.SUSPICIOUS_AGENT]
        assert any("nikto" in e.details.get("user_agent", "").lower() for e in agent_events)

    def test_sql_injection_in_url(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.SQL_INJECTION in types

    def test_xss_in_url(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.XSS_ATTEMPT in types

    def test_directory_traversal(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.DIRECTORY_TRAVERSAL in types

    def test_scanner_path_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.SCANNER_DETECTED in types

    def test_empty_ua_detected(self):
        agent_events = [e for e in self.result.events if e.event_type == EventType.SUSPICIOUS_AGENT]
        assert any(not e.details.get("user_agent") for e in agent_events)

    def test_http_brute_force(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.BRUTE_FORCE in types


# ── Windows Event Log XML ─────────────────────────────────────────────────────

class TestWindowsEventLog:
    def setup_method(self):
        self.result = analyse(FIXTURES / "windows_events.xml")

    def test_log_type_detected(self):
        assert self.result.log_type == "windows_event"

    def test_failed_logon_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.FAILED_LOGIN in types

    def test_failed_logon_ip(self):
        failed = [e for e in self.result.events if e.event_type == EventType.FAILED_LOGIN]
        assert any(e.source_ip == "192.168.1.200" for e in failed)

    def test_special_privileges_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.SPECIAL_PRIVILEGES in types

    def test_account_created(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.ACCOUNT_CREATED in types

    def test_group_modified(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.GROUP_MODIFIED in types

    def test_service_installed_is_critical(self):
        svc = [e for e in self.result.events if e.event_type == EventType.SERVICE_INSTALLED]
        assert svc
        assert all(e.severity == Severity.CRITICAL for e in svc)

    def test_log_cleared_is_critical(self):
        cleared = [e for e in self.result.events if e.event_type == EventType.LOG_CLEARED]
        assert cleared
        assert all(e.severity == Severity.CRITICAL for e in cleared)

    def test_scheduled_task_detected(self):
        types = [e.event_type for e in self.result.events]
        assert EventType.SCHEDULED_TASK in types


# ── Severity filtering ────────────────────────────────────────────────────────

class TestSeverityFilter:
    def test_filter_high_only(self):
        result = analyse(FIXTURES / "auth.log", min_severity=Severity.HIGH)
        for event in result.events:
            assert event.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_filter_critical_only(self):
        result = analyse(FIXTURES / "auth.log", min_severity=Severity.CRITICAL)
        for event in result.events:
            assert event.severity == Severity.CRITICAL


# ── Brute-force threshold ─────────────────────────────────────────────────────

class TestBruteForceThreshold:
    def test_custom_threshold_low(self):
        # With threshold=2, we expect brute-force to be flagged from 2 failures
        result = analyse(FIXTURES / "auth.log", brute_force_threshold=2)
        bf = [e for e in result.events if e.event_type == EventType.BRUTE_FORCE]
        assert bf

    def test_custom_threshold_high(self):
        # With a very high threshold, no brute-force should be flagged in small fixture
        result = analyse(FIXTURES / "auth.log", brute_force_threshold=1000)
        bf = [e for e in result.events if e.event_type == EventType.BRUTE_FORCE]
        assert not bf
