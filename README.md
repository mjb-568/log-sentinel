# log-sentinel

A Python CLI tool that ingests common log formats and extracts security-relevant events: failed logins, brute-force attacks, privilege escalation, and suspicious HTTP activity.

## Supported Log Formats

| Format | Flag | Auto-detected |
|---|---|---|
| Linux `auth.log` / `secure` | `--type auth` | Yes |
| Apache / Nginx access log (Combined Log Format) | `--type apache` | Yes |
| Windows Event Log (exported XML) | `--type windows` | Yes (`.xml`) |

## Detected Events

### Failed Logins & Brute-Force
- SSH failed password and invalid user attempts
- PAM authentication failures
- HTTP 401 bursts (web brute-force)
- Windows Event 4625 (failed logon), 4776 (NTLM credential validation)
- **Brute-force flagging** configurable threshold + time window

### Privilege Escalation
- `sudo` command execution (with sensitivity rating for shells, passwd, iptables, etc.)
- `sudo` failures — wrong password or not in sudoers
- `su` authentication failures
- New user account creation (`useradd`)
- Group membership changes (`usermod`) — escalated severity for `sudo`/`wheel`
- Windows Event 4672 (special privileges), 4648 (explicit credentials)
- Windows Event 4720 (user created), 4728/4732/4756 (group membership)
- Windows Event 7045 (new service installed), 1102 (audit log cleared)
- Windows Event 4698/4702 (scheduled tasks)

### Suspicious HTTP Activity
- Known scanner/tool user agents: `sqlmap`, `nikto`, `nmap`, `masscan`, `metasploit`, `dirbuster`, `gobuster`, `hydra`, and more
- Directory traversal (`../`, URL-encoded variants)
- SQL injection patterns in URL parameters
- XSS payloads in URLs
- Common attack paths (`/phpmyadmin`, `/.env`, `/wp-login.php`, `/shell.php`, etc.)
- Empty / missing User-Agent strings

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/log-sentinel.git
cd log-sentinel
pip install -e .
```

Or install directly:
```bash
pip install -e ".[dev]"   # includes pytest for running tests
```

**Requires Python 3.9+ and `rich`.**

## Usage

```
log-sentinel LOG_FILE [options]
```

### Options

```
--type, -t {auto,auth,apache,windows}
                      Log format (default: auto-detect)
--output, -f {table,json,csv}
                      Output format (default: table)
-o, --out FILE        Write output to FILE
--severity, -s {low,medium,high,critical}
                      Minimum severity to report (default: low)
--brute-threshold N   Failures before flagging brute-force (default: 5)
--brute-window MINS   Time window for brute-force detection (default: 10)
--no-color            Disable colour output
```

### Examples

```bash
# Analyse a Linux auth log (auto-detected)
log-sentinel /var/log/auth.log

# Analyse Apache access log, only show high+ severity
log-sentinel /var/log/apache2/access.log --type apache --severity high

# Export Windows Event XML analysis as JSON
log-sentinel events.xml --output json -o report.json

# Lower the brute-force threshold to 3 failures in 5 minutes
log-sentinel auth.log --brute-threshold 3 --brute-window 5

# Use the sample fixtures to try it out immediately
log-sentinel tests/fixtures/auth.log
log-sentinel tests/fixtures/access.log
log-sentinel tests/fixtures/windows_events.xml
```

## Output

### Table (default)
Rich terminal table with colour-coded severity, timestamps, event types, users, and source IPs, plus a brute-force summary section.

### JSON
```json
{
  "log_file": "auth.log",
  "log_type": "auth_log",
  "total_lines": 16,
  "event_count": 12,
  "summary": { "critical": 2, "high": 5, "by_type": {...} },
  "events": [...]
}
```

### CSV
Standard CSV with columns: `timestamp`, `event_type`, `severity`, `source_ip`, `user`, `description`, `log_type`, `line_number`.

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Architecture

```
log_sentinel/
├── models.py          # SecurityEvent, AnalysisResult, Severity, EventType
├── engine.py          # Wires parser → detectors → AnalysisResult
├── cli.py             # argparse CLI entry point
├── parsers/
│   ├── auth_log.py    # Linux syslog/auth.log parser
│   ├── apache.py      # Apache/Nginx combined log format parser
│   └── windows_event.py  # Windows Event Log XML parser
├── detectors/
│   ├── failed_logins.py         # Failed login + brute-force detection
│   ├── privilege_escalation.py  # sudo, su, account/group changes, Windows events
│   └── suspicious_agents.py     # Malicious UAs, path traversal, SQLi, XSS
└── reporters/
    ├── console.py     # Rich terminal output
    └── exporters.py   # JSON and CSV export
```

## License

MIT
