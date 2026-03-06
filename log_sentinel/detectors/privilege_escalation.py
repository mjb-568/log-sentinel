"""Detect privilege escalation attempts."""

import re
from typing import Any, Dict, List, Optional

from ..models import EventType, SecurityEvent, Severity

# sudo successful execution
_SUDO_CMD_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:.*?USER=(?P<as_user>\S+)\s*;.*?COMMAND=(?P<cmd>.+)",
    re.IGNORECASE,
)
# sudo authentication failure
_SUDO_FAIL_RE = re.compile(
    r"sudo:.*?authentication failure.*?user=(?P<user>\S+)",
    re.IGNORECASE,
)
# sudo: user is not in the sudoers file
_SUDO_NOT_ALLOWED_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:.*?(?:NOT in sudoers|not allowed to execute)",
    re.IGNORECASE,
)
# su failure
_SU_FAIL_RE = re.compile(
    r"su\b.*?pam_unix.*?authentication failure.*?user=(?P<user>\S+)",
    re.IGNORECASE,
)
# su: FAILED SU
_SU_FAILED_RE = re.compile(
    r"su\b.*?FAILED SU.*?(?:user=(?P<user>\S+)|by (?P<by>\S+))",
    re.IGNORECASE,
)
# New user created
_NEW_USER_RE = re.compile(
    r"(?:useradd|adduser)\[.*?\]:\s+new user:\s+name=(?P<name>\S+)",
    re.IGNORECASE,
)
# usermod adding to group
_USERMOD_GROUP_RE = re.compile(
    r"usermod\[.*?\]:\s+add\s+'(?P<user>[^']+)'\s+to\s+(?:group|shadow group)\s+'(?P<group>[^']+)'",
    re.IGNORECASE,
)
# groupadd
_GROUP_ADD_RE = re.compile(
    r"(?:groupadd|addgroup)\[.*?\]:\s+new group:\s+name=(?P<name>\S+)",
    re.IGNORECASE,
)

# Sensitive commands that warrant escalation alerts
_SENSITIVE_CMDS = re.compile(
    r"(?:/bin/(?:bash|sh|zsh|fish|dash)|/usr/bin/(?:bash|sh|python\S*|perl\S*|ruby\S*)"
    r"|passwd|visudo|/etc/sudoers|chmod\s+[0-7]*[46][0-7][0-7]|chown\s+root"
    r"|iptables|systemctl|service\s+\S+\s+(?:start|stop|restart)|crontab)",
    re.IGNORECASE,
)

# Windows Event IDs for privilege escalation
_WIN_PRIV_IDS = {
    4672: ("Special privileges assigned to new logon", Severity.HIGH),
    4648: ("Logon attempt with explicit credentials", Severity.MEDIUM),
    4698: ("Scheduled task created", Severity.HIGH),
    4702: ("Scheduled task updated", Severity.MEDIUM),
    4720: ("User account created", Severity.HIGH),
    4728: ("Member added to security-enabled global group", Severity.HIGH),
    4732: ("Member added to security-enabled local group", Severity.HIGH),
    4756: ("Member added to security-enabled universal group", Severity.HIGH),
    7045: ("New Windows service installed", Severity.CRITICAL),
    1102: ("Audit log cleared", Severity.CRITICAL),
}


class PrivilegeEscalationDetector:

    def detect(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        log_type = record.get("log_type", "")
        if log_type == "auth_log":
            return self._detect_auth_log(record)
        if log_type == "windows_event":
            return self._detect_windows(record)
        return []

    def _make_event(
        self,
        record: Dict[str, Any],
        event_type: EventType,
        severity: Severity,
        description: str,
        user: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        return SecurityEvent(
            timestamp=record.get("timestamp"),
            event_type=event_type,
            severity=severity,
            source_ip=record.get("source_ip"),
            user=user or record.get("user"),
            description=description,
            raw_line=record.get("raw", ""),
            log_type=record.get("log_type", ""),
            line_number=record.get("line_number", 0),
            details=details or {},
        )

    def _detect_auth_log(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        # Search the raw syslog line so process-prefixed patterns (sudo:, useradd[..]:)
        # are present.  message alone is stripped of those prefixes.
        raw = record.get("raw", "")
        events: List[SecurityEvent] = []

        # sudo command executed successfully
        m = _SUDO_CMD_RE.search(raw)
        if m:
            user = m.group("user")
            as_user = m.group("as_user")
            cmd = m.group("cmd").strip()
            is_sensitive = bool(_SENSITIVE_CMDS.search(cmd))
            severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
            events.append(
                self._make_event(
                    record,
                    EventType.SUDO_COMMAND,
                    severity,
                    f"sudo: '{user}' ran '{cmd[:80]}' as {as_user}",
                    user=user,
                    details={"command": cmd, "as_user": as_user, "sensitive": is_sensitive},
                )
            )
            return events

        # sudo: not in sudoers
        m = _SUDO_NOT_ALLOWED_RE.search(raw)
        if m:
            user = m.group("user")
            events.append(
                self._make_event(
                    record,
                    EventType.SUDO_FAILURE,
                    Severity.HIGH,
                    f"Unauthorized sudo attempt by '{user}' (not in sudoers)",
                    user=user,
                    details={"reason": "not_in_sudoers"},
                )
            )
            return events

        # sudo authentication failure
        m = _SUDO_FAIL_RE.search(raw)
        if m:
            user = m.group("user")
            events.append(
                self._make_event(
                    record,
                    EventType.SUDO_FAILURE,
                    Severity.MEDIUM,
                    f"sudo authentication failure for '{user}'",
                    user=user,
                    details={"reason": "auth_failure"},
                )
            )
            return events

        # su failure
        m = _SU_FAIL_RE.search(raw) or _SU_FAILED_RE.search(raw)
        if m:
            user = m.group("user") if "user" in m.groupdict() and m.group("user") else None
            events.append(
                self._make_event(
                    record,
                    EventType.SU_FAILURE,
                    Severity.MEDIUM,
                    f"su authentication failure" + (f" for '{user}'" if user else ""),
                    user=user,
                    details={"reason": "su_auth_failure"},
                )
            )
            return events

        # New user created
        m = _NEW_USER_RE.search(raw)
        if m:
            name = m.group("name").rstrip(",")
            events.append(
                self._make_event(
                    record,
                    EventType.ACCOUNT_CREATED,
                    Severity.HIGH,
                    f"New user account created: '{name}'",
                    user=name,
                    details={"new_user": name},
                )
            )
            return events

        # usermod group add
        m = _USERMOD_GROUP_RE.search(raw)
        if m:
            user, group = m.group("user"), m.group("group")
            severity = Severity.HIGH if group.lower() in ("sudo", "wheel", "admin", "root") else Severity.MEDIUM
            events.append(
                self._make_event(
                    record,
                    EventType.GROUP_MODIFIED,
                    severity,
                    f"User '{user}' added to group '{group}'",
                    user=user,
                    details={"user": user, "group": group},
                )
            )
            return events

        return events

    def _detect_windows(self, record: Dict[str, Any]) -> List[SecurityEvent]:
        event_id = record.get("event_id", 0)
        edata = record.get("event_data", {})
        events: List[SecurityEvent] = []

        if event_id not in _WIN_PRIV_IDS:
            return events

        description_tmpl, severity = _WIN_PRIV_IDS[event_id]

        # Build a richer description for specific events
        if event_id == 4672:
            user = edata.get("SubjectUserName", "unknown")
            privs = edata.get("PrivilegeList", "").strip()
            description = f"Special privileges assigned to '{user}': {privs[:100]}"
        elif event_id == 4648:
            user = edata.get("SubjectUserName", "unknown")
            target = edata.get("TargetUserName", "?")
            description = f"Explicit credential logon: '{user}' used creds for '{target}'"
        elif event_id in (4698, 4702):
            user = edata.get("SubjectUserName", "unknown")
            task = edata.get("TaskName", "?")
            description = f"Scheduled task {'created' if event_id == 4698 else 'updated'}: '{task}' by '{user}'"
        elif event_id == 4720:
            user = edata.get("TargetUserName", "unknown")
            creator = edata.get("SubjectUserName", "?")
            description = f"User account created: '{user}' by '{creator}'"
        elif event_id in (4728, 4732, 4756):
            member = edata.get("MemberName") or edata.get("TargetUserName", "?")
            group = edata.get("TargetUserName") or edata.get("GroupName", "?")
            description = f"Member '{member}' added to group '{group}'"
        elif event_id == 7045:
            svc = edata.get("ServiceName", "?")
            file_name = edata.get("ImagePath", "?")
            description = f"New service installed: '{svc}' ({file_name[:80]})"
        elif event_id == 1102:
            user = edata.get("SubjectUserName", "unknown")
            description = f"Security audit log cleared by '{user}' — CRITICAL"
        else:
            description = description_tmpl

        event_type_map = {
            4672: EventType.SPECIAL_PRIVILEGES,
            4648: EventType.EXPLICIT_CREDENTIALS,
            4698: EventType.SCHEDULED_TASK,
            4702: EventType.SCHEDULED_TASK,
            4720: EventType.ACCOUNT_CREATED,
            4728: EventType.GROUP_MODIFIED,
            4732: EventType.GROUP_MODIFIED,
            4756: EventType.GROUP_MODIFIED,
            7045: EventType.SERVICE_INSTALLED,
            1102: EventType.LOG_CLEARED,
        }

        events.append(
            self._make_event(
                record,
                event_type_map.get(event_id, EventType.PRIVILEGE_ESCALATION),
                severity,
                description,
                user=record.get("user"),
                details={"event_id": event_id, **edata},
            )
        )
        return events
