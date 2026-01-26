"""
LogParser Module - Parses and normalizes security log files.

Supports multiple log formats:
- Syslog (RFC 3164 and RFC 5424 style)
- JSON formatted logs
- CSV formatted logs

Author: CyberRisk Team
"""

import csv
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Iterator

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """
    Represents a normalized log entry from any supported format.

    All log entries are converted to this common format for consistent
    processing by the RuleEngine and RiskScorer.
    """
    timestamp: datetime
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    event_type: str = "unknown"
    user: Optional[str] = None
    message: str = ""
    raw_data: str = ""
    severity: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    port: Optional[int] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert LogEntry to dictionary representation."""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "event_type": self.event_type,
            "user": self.user,
            "message": self.message,
            "raw_data": self.raw_data,
            "severity": self.severity,
            "hostname": self.hostname,
            "process": self.process,
            "port": self.port,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LogEntry":
        """Create LogEntry from dictionary."""
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        elif timestamp is None:
            timestamp = datetime.now()

        return cls(
            timestamp=timestamp,
            source_ip=data.get("source_ip"),
            dest_ip=data.get("dest_ip"),
            event_type=data.get("event_type", "unknown"),
            user=data.get("user"),
            message=data.get("message", ""),
            raw_data=data.get("raw_data", ""),
            severity=data.get("severity"),
            hostname=data.get("hostname"),
            process=data.get("process"),
            port=data.get("port"),
            metadata=data.get("metadata", {}),
        )

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"[{self.timestamp}] {self.event_type}: {self.message[:100]}"


class LogParser:
    """
    Parses security log files in multiple formats.

    Supports automatic format detection and normalization of log entries
    into a common LogEntry format for downstream processing.

    Supported formats:
        - syslog: Traditional syslog format (RFC 3164 style)
        - json: JSON formatted logs (one object per line or array)
        - csv: CSV formatted logs with headers

    Example:
        parser = LogParser()
        entries = parser.parse_file("security.log")
        for entry in entries:
            print(entry.event_type, entry.message)
    """

    # Syslog regex patterns
    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )

    # Alternative syslog pattern with ISO timestamp
    SYSLOG_ISO_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )

    # IP address pattern
    IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    # Common event type patterns
    EVENT_PATTERNS = {
        "authentication_failure": re.compile(
            r'(failed|invalid|bad)\s+(password|login|auth)', re.IGNORECASE
        ),
        "authentication_success": re.compile(
            r'(accepted|successful)\s+(password|login|auth)', re.IGNORECASE
        ),
        "ssh_connection": re.compile(
            r'(sshd|ssh)', re.IGNORECASE
        ),
        "sudo_command": re.compile(
            r'sudo', re.IGNORECASE
        ),
        "privilege_escalation": re.compile(
            r'(root|admin|privilege|escalat)', re.IGNORECASE
        ),
        "port_scan": re.compile(
            r'(scan|probe|connection\s+refused)', re.IGNORECASE
        ),
        "service_start": re.compile(
            r'(started|starting|service\s+start)', re.IGNORECASE
        ),
        "service_stop": re.compile(
            r'(stopped|stopping|service\s+stop)', re.IGNORECASE
        ),
        "file_access": re.compile(
            r'(open|read|write|access|permission)', re.IGNORECASE
        ),
        "network_connection": re.compile(
            r'(connect|connection|session)', re.IGNORECASE
        ),
    }

    # User extraction patterns
    USER_PATTERNS = [
        re.compile(r'user[=:\s]+["\']?(\w+)["\']?', re.IGNORECASE),
        re.compile(r'for\s+(?:user\s+)?["\']?(\w+)["\']?', re.IGNORECASE),
        re.compile(r'from\s+(?:user\s+)?["\']?(\w+)["\']?', re.IGNORECASE),
        re.compile(r'account[=:\s]+["\']?(\w+)["\']?', re.IGNORECASE),
    ]

    def __init__(self):
        """Initialize the LogParser."""
        self.supported_formats = ["syslog", "json", "csv"]
        self.errors: list[str] = []
        self._current_year = datetime.now().year

    def parse_file(self, file_path: str | Path) -> list[LogEntry]:
        """
        Parse a log file and return a list of LogEntry objects.

        Automatically detects the file format based on content and extension.

        Args:
            file_path: Path to the log file

        Returns:
            List of parsed LogEntry objects

        Raises:
            FileNotFoundError: If the file does not exist
            ValueError: If the file format cannot be determined
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        self.errors = []

        # Detect format
        file_format = self._detect_format(file_path)
        logger.info(f"Detected format '{file_format}' for file: {file_path}")

        # Parse based on format
        if file_format == "json":
            return self.parse_json(file_path)
        elif file_format == "csv":
            return self.parse_csv(file_path)
        else:  # syslog
            return self.parse_syslog(file_path)

    def _detect_format(self, file_path: Path) -> str:
        """
        Detect the format of a log file.

        Uses file extension as hint and validates with content inspection.
        """
        extension = file_path.suffix.lower()

        # Check extension first
        if extension == ".json":
            return "json"
        elif extension == ".csv":
            return "csv"

        # Read first few lines to detect format
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                first_lines = [f.readline() for _ in range(5)]
                first_content = "".join(first_lines).strip()
        except Exception as e:
            logger.warning(f"Error reading file for format detection: {e}")
            return "syslog"

        if not first_content:
            return "syslog"

        # Check for JSON
        if first_content.startswith("{") or first_content.startswith("["):
            return "json"

        # Check for CSV (look for comma-separated headers)
        first_line = first_lines[0].strip()
        if "," in first_line and not self.SYSLOG_PATTERN.match(first_line):
            # Count commas in first few lines - CSV should be consistent
            comma_counts = [line.count(",") for line in first_lines if line.strip()]
            if comma_counts and len(set(comma_counts)) <= 2:  # Allow some variation
                return "csv"

        return "syslog"

    def parse_syslog(self, file_path: str | Path) -> list[LogEntry]:
        """
        Parse a syslog format file.

        Supports both traditional BSD syslog (RFC 3164) and ISO timestamp formats.

        Args:
            file_path: Path to the syslog file

        Returns:
            List of parsed LogEntry objects
        """
        entries = []
        file_path = Path(file_path)

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = self._parse_syslog_line(line)
                    if entry:
                        entries.append(entry)
                except Exception as e:
                    error_msg = f"Line {line_num}: {str(e)}"
                    self.errors.append(error_msg)
                    logger.debug(f"Failed to parse syslog line: {error_msg}")

        logger.info(f"Parsed {len(entries)} entries from syslog file")
        return entries

    def _parse_syslog_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single syslog line into a LogEntry."""
        # Try ISO timestamp pattern first
        match = self.SYSLOG_ISO_PATTERN.match(line)
        if match:
            groups = match.groupdict()
            timestamp = self._parse_iso_timestamp(groups["timestamp"])
        else:
            # Try traditional syslog pattern
            match = self.SYSLOG_PATTERN.match(line)
            if match:
                groups = match.groupdict()
                timestamp = self._parse_syslog_timestamp(groups["timestamp"])
            else:
                # Fallback: create basic entry with current timestamp
                return LogEntry(
                    timestamp=datetime.now(),
                    message=line,
                    raw_data=line,
                    event_type=self._detect_event_type(line),
                )

        message = groups.get("message", "")

        # Extract additional fields from message
        source_ip, dest_ip = self._extract_ips(message)
        user = self._extract_user(message)
        event_type = self._detect_event_type(message)
        port = self._extract_port(message)

        return LogEntry(
            timestamp=timestamp,
            hostname=groups.get("hostname"),
            process=groups.get("process"),
            message=message,
            raw_data=line,
            source_ip=source_ip,
            dest_ip=dest_ip,
            user=user,
            event_type=event_type,
            port=port,
            metadata={"pid": groups.get("pid")},
        )

    def _parse_syslog_timestamp(self, timestamp_str: str) -> datetime:
        """Parse traditional syslog timestamp (e.g., 'Jan  5 14:32:01')."""
        try:
            # Add current year since syslog doesn't include it
            parsed = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            return parsed.replace(year=self._current_year)
        except ValueError:
            try:
                parsed = datetime.strptime(timestamp_str, "%b  %d %H:%M:%S")
                return parsed.replace(year=self._current_year)
            except ValueError:
                return datetime.now()

    def _parse_iso_timestamp(self, timestamp_str: str) -> datetime:
        """Parse ISO format timestamp."""
        # Handle various ISO formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]

        # Remove timezone suffix for parsing
        clean_ts = re.sub(r'[+-]\d{2}:?\d{2}$', '', timestamp_str)

        for fmt in formats:
            try:
                return datetime.strptime(clean_ts, fmt)
            except ValueError:
                continue

        return datetime.now()

    def parse_json(self, file_path: str | Path) -> list[LogEntry]:
        """
        Parse a JSON format log file.

        Supports both JSON Lines format (one object per line) and
        a single JSON array containing all entries.

        Args:
            file_path: Path to the JSON log file

        Returns:
            List of parsed LogEntry objects
        """
        entries = []
        file_path = Path(file_path)

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        if not content:
            return entries

        # Try parsing as JSON array first
        if content.startswith("["):
            try:
                data = json.loads(content)
                for i, item in enumerate(data):
                    try:
                        entry = self._parse_json_object(item)
                        if entry:
                            entries.append(entry)
                    except Exception as e:
                        self.errors.append(f"Item {i}: {str(e)}")
                return entries
            except json.JSONDecodeError:
                pass  # Fall through to JSON Lines parsing

        # Parse as JSON Lines (one object per line)
        for line_num, line in enumerate(content.split("\n"), 1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                entry = self._parse_json_object(data)
                if entry:
                    entries.append(entry)
            except json.JSONDecodeError as e:
                self.errors.append(f"Line {line_num}: Invalid JSON - {str(e)}")
            except Exception as e:
                self.errors.append(f"Line {line_num}: {str(e)}")

        logger.info(f"Parsed {len(entries)} entries from JSON file")
        return entries

    def _parse_json_object(self, data: dict) -> Optional[LogEntry]:
        """Parse a JSON object into a LogEntry."""
        if not isinstance(data, dict):
            return None

        # Extract timestamp with various possible field names
        timestamp = None
        for ts_field in ["timestamp", "time", "@timestamp", "datetime", "date", "ts"]:
            if ts_field in data:
                timestamp = self._parse_json_timestamp(data[ts_field])
                break

        if timestamp is None:
            timestamp = datetime.now()

        # Extract common fields with fallbacks
        message = data.get("message") or data.get("msg") or data.get("log") or str(data)

        source_ip = data.get("source_ip") or data.get("src_ip") or data.get("client_ip")
        dest_ip = data.get("dest_ip") or data.get("dst_ip") or data.get("server_ip")

        if not source_ip:
            source_ip, _ = self._extract_ips(message)

        user = data.get("user") or data.get("username") or data.get("account")
        if not user:
            user = self._extract_user(message)

        event_type = data.get("event_type") or data.get("type") or data.get("action")
        if not event_type:
            event_type = self._detect_event_type(message)

        severity = data.get("severity") or data.get("level") or data.get("priority")
        hostname = data.get("hostname") or data.get("host") or data.get("server")
        process = data.get("process") or data.get("program") or data.get("service")
        port = data.get("port") or data.get("dest_port") or data.get("dst_port")

        if port and isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                port = None

        # Store remaining fields as metadata
        known_fields = {
            "timestamp", "time", "@timestamp", "datetime", "date", "ts",
            "message", "msg", "log", "source_ip", "src_ip", "client_ip",
            "dest_ip", "dst_ip", "server_ip", "user", "username", "account",
            "event_type", "type", "action", "severity", "level", "priority",
            "hostname", "host", "server", "process", "program", "service",
            "port", "dest_port", "dst_port",
        }
        metadata = {k: v for k, v in data.items() if k not in known_fields}

        return LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            event_type=event_type,
            user=user,
            message=str(message),
            raw_data=json.dumps(data),
            severity=str(severity) if severity else None,
            hostname=hostname,
            process=process,
            port=port,
            metadata=metadata,
        )

    def _parse_json_timestamp(self, value) -> Optional[datetime]:
        """Parse timestamp from JSON value (string or unix timestamp)."""
        if isinstance(value, (int, float)):
            # Unix timestamp (seconds or milliseconds)
            if value > 1e11:  # Likely milliseconds
                value = value / 1000
            try:
                return datetime.fromtimestamp(value)
            except (ValueError, OSError):
                return None

        if isinstance(value, str):
            return self._parse_iso_timestamp(value)

        return None

    def parse_csv(self, file_path: str | Path) -> list[LogEntry]:
        """
        Parse a CSV format log file.

        Expects the first row to contain column headers. Maps common
        header names to LogEntry fields.

        Args:
            file_path: Path to the CSV log file

        Returns:
            List of parsed LogEntry objects
        """
        entries = []
        file_path = Path(file_path)

        with open(file_path, "r", encoding="utf-8", errors="replace", newline="") as f:
            # Detect delimiter
            sample = f.read(4096)
            f.seek(0)

            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel

            reader = csv.DictReader(f, dialect=dialect)

            for row_num, row in enumerate(reader, 2):  # Start at 2 (header is row 1)
                try:
                    entry = self._parse_csv_row(row)
                    if entry:
                        entries.append(entry)
                except Exception as e:
                    self.errors.append(f"Row {row_num}: {str(e)}")

        logger.info(f"Parsed {len(entries)} entries from CSV file")
        return entries

    def _parse_csv_row(self, row: dict) -> Optional[LogEntry]:
        """Parse a CSV row into a LogEntry."""
        # Normalize column names (lowercase, strip whitespace)
        row = {k.lower().strip(): v for k, v in row.items() if v}

        if not row:
            return None

        # Extract timestamp
        timestamp = None
        for ts_field in ["timestamp", "time", "datetime", "date", "ts", "event_time"]:
            if ts_field in row:
                timestamp = self._parse_iso_timestamp(row[ts_field])
                break

        if timestamp is None:
            timestamp = datetime.now()

        # Build message from available fields if not present
        message = row.get("message") or row.get("msg") or row.get("log") or row.get("description")
        if not message:
            message = " | ".join(f"{k}={v}" for k, v in row.items())

        source_ip = row.get("source_ip") or row.get("src_ip") or row.get("client_ip") or row.get("source")
        dest_ip = row.get("dest_ip") or row.get("dst_ip") or row.get("destination") or row.get("server_ip")
        user = row.get("user") or row.get("username") or row.get("account") or row.get("userid")
        event_type = row.get("event_type") or row.get("type") or row.get("action") or row.get("event")

        if not event_type:
            event_type = self._detect_event_type(message)

        severity = row.get("severity") or row.get("level") or row.get("priority")
        hostname = row.get("hostname") or row.get("host") or row.get("server") or row.get("computer")
        process = row.get("process") or row.get("program") or row.get("service") or row.get("application")

        port = row.get("port") or row.get("dest_port") or row.get("dst_port")
        if port:
            try:
                port = int(port)
            except ValueError:
                port = None

        return LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            dest_ip=dest_ip,
            event_type=event_type,
            user=user,
            message=message,
            raw_data=str(row),
            severity=severity,
            hostname=hostname,
            process=process,
            port=port,
            metadata={},
        )

    def _extract_ips(self, text: str) -> tuple[Optional[str], Optional[str]]:
        """Extract IP addresses from text."""
        ips = self.IP_PATTERN.findall(text)

        # Validate IPs and filter out obvious non-IPs
        valid_ips = []
        for ip in ips:
            octets = ip.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                valid_ips.append(ip)

        if len(valid_ips) >= 2:
            return valid_ips[0], valid_ips[1]
        elif len(valid_ips) == 1:
            return valid_ips[0], None
        return None, None

    def _extract_user(self, text: str) -> Optional[str]:
        """Extract username from text."""
        for pattern in self.USER_PATTERNS:
            match = pattern.search(text)
            if match:
                user = match.group(1)
                # Filter out common false positives
                if user.lower() not in ["invalid", "unknown", "none", "null", "root"]:
                    return user
                elif user.lower() == "root":
                    return user
        return None

    def _extract_port(self, text: str) -> Optional[int]:
        """Extract port number from text."""
        # Look for port patterns
        port_patterns = [
            re.compile(r'port[=:\s]+(\d+)', re.IGNORECASE),
            re.compile(r':(\d{2,5})(?:\s|$)'),
        ]

        for pattern in port_patterns:
            match = pattern.search(text)
            if match:
                try:
                    port = int(match.group(1))
                    if 1 <= port <= 65535:
                        return port
                except ValueError:
                    pass
        return None

    def _detect_event_type(self, text: str) -> str:
        """Detect event type from message text."""
        for event_type, pattern in self.EVENT_PATTERNS.items():
            if pattern.search(text):
                return event_type
        return "unknown"

    def get_errors(self) -> list[str]:
        """Return list of parsing errors encountered."""
        return self.errors.copy()

    def parse_directory(self, dir_path: str | Path, pattern: str = "*") -> list[LogEntry]:
        """
        Parse all log files in a directory.

        Args:
            dir_path: Path to directory containing log files
            pattern: Glob pattern for matching files (default: all files)

        Returns:
            Combined list of LogEntry objects from all files
        """
        dir_path = Path(dir_path)
        entries = []

        for file_path in dir_path.glob(pattern):
            if file_path.is_file():
                try:
                    file_entries = self.parse_file(file_path)
                    entries.extend(file_entries)
                except Exception as e:
                    self.errors.append(f"File {file_path}: {str(e)}")

        return entries
