"""Parser for Windows Event Logs exported as XML.

Handles both single-event XML files and the standard export format that wraps
multiple <Event> elements inside an <Events> root element.

Key Event IDs detected:
    4624  - Successful logon
    4625  - Failed logon
    4648  - Logon with explicit credentials
    4672  - Special privileges assigned to new logon
    4698  - Scheduled task created
    4702  - Scheduled task updated
    4720  - User account created
    4728  - Member added to security-enabled global group
    4732  - Member added to security-enabled local group
    4756  - Member added to security-enabled universal group
    4776  - Credential validation (NTLM)
    7045  - New service installed (System log)
    1102  - Audit log cleared
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, Optional

from .base import BaseParser

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_SYS_NS = f"{{{_NS}}}System"
_DATA_NS = f"{{{_NS}}}EventData"
_USER_DATA_NS = f"{{{_NS}}}UserData"


def _tag(name: str) -> str:
    return f"{{{_NS}}}{name}"


def _parse_ts(raw: str) -> Optional[datetime]:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _extract_system(system_el: ET.Element) -> Dict[str, Any]:
    def find_text(tag: str) -> Optional[str]:
        el = system_el.find(_tag(tag))
        return el.text if el is not None else None

    def find_attr(tag: str, attr: str) -> Optional[str]:
        el = system_el.find(_tag(tag))
        return el.get(attr) if el is not None else None

    event_id_el = system_el.find(_tag("EventID"))
    event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0

    ts_raw = find_attr("TimeCreated", "SystemTime") or ""
    return {
        "event_id": event_id,
        "timestamp": _parse_ts(ts_raw),
        "provider": find_attr("Provider", "Name"),
        "computer": find_text("Computer"),
        "channel": find_text("Channel"),
        "record_id": find_text("EventRecordID"),
    }


def _extract_event_data(event_el: ET.Element) -> Dict[str, str]:
    data: Dict[str, str] = {}

    for section_tag in (_DATA_NS, _USER_DATA_NS):
        section = event_el.find(f"{{{_NS}}}{section_tag.split('}')[1]}")
        if section is None:
            # Try without namespace stripping
            for child in event_el:
                local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if local in ("EventData", "UserData"):
                    section = child
                    break
        if section is not None:
            for data_el in section:
                name = data_el.get("Name") or data_el.tag.split("}")[-1]
                data[name] = data_el.text or ""

    return data


def _parse_event(event_el: ET.Element, lineno: int) -> Optional[Dict[str, Any]]:
    system_el = event_el.find(_tag("System"))
    if system_el is None:
        return None

    sys_info = _extract_system(system_el)
    event_data = _extract_event_data(event_el)

    raw = ET.tostring(event_el, encoding="unicode")

    return {
        **sys_info,
        "event_data": event_data,
        "raw": raw,
        "line_number": lineno,
        "log_type": "windows_event",
        # Convenience aliases used by detectors
        "source_ip": event_data.get("IpAddress") or event_data.get("WorkstationName"),
        "user": (
            event_data.get("TargetUserName")
            or event_data.get("SubjectUserName")
            or event_data.get("MemberName")
        ),
    }


class WindowsEventLogParser(BaseParser):
    log_type = "windows_event"

    def parse(self, path: Path) -> Generator[Dict[str, Any], None, None]:
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError as exc:
            raise ValueError(f"XML parse error in {path}: {exc}") from exc

        # Root may be <Events> wrapping many <Event> elements, or a single <Event>
        local_root = root.tag.split("}")[-1] if "}" in root.tag else root.tag

        if local_root == "Events":
            events = list(root)
        elif local_root == "Event":
            events = [root]
        else:
            # Try to find Event elements anywhere
            events = root.findall(f".//{_tag('Event')}")
            if not events:
                events = root.findall(".//Event")

        for idx, event_el in enumerate(events, 1):
            record = _parse_event(event_el, idx)
            if record:
                yield record

    @classmethod
    def sniff(cls, path: Path) -> bool:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(512)
            return (
                "xmlns" in head
                and "schemas.microsoft.com/win/2004/08/events" in head
            ) or ("<Events>" in head or "<Event " in head)
        except OSError:
            return False
