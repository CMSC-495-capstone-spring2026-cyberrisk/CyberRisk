"""
Unit tests for the LogParser module.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cyberrisk.core.log_parser import LogParser, LogEntry


class TestLogEntry:
    """Tests for LogEntry dataclass."""

    def test_create_log_entry(self):
        """Test creating a LogEntry with required fields."""
        entry = LogEntry(
            timestamp=datetime.now(),
            message="Test message",
        )
        assert entry.message == "Test message"
        assert entry.event_type == "unknown"

    def test_log_entry_to_dict(self):
        """Test converting LogEntry to dictionary."""
        timestamp = datetime(2026, 1, 26, 10, 0, 0)
        entry = LogEntry(
            timestamp=timestamp,
            source_ip="192.168.1.100",
            message="Failed login",
            event_type="authentication_failure",
        )
        data = entry.to_dict()

        assert data["source_ip"] == "192.168.1.100"
        assert data["event_type"] == "authentication_failure"
        assert "2026-01-26" in data["timestamp"]

    def test_log_entry_from_dict(self):
        """Test creating LogEntry from dictionary."""
        data = {
            "timestamp": "2026-01-26T10:00:00",
            "source_ip": "10.0.0.1",
            "message": "Test message",
            "event_type": "network_connection",
        }
        entry = LogEntry.from_dict(data)

        assert entry.source_ip == "10.0.0.1"
        assert entry.event_type == "network_connection"


class TestLogParser:
    """Tests for LogParser class."""

    def test_parser_initialization(self):
        """Test LogParser initialization."""
        parser = LogParser()
        assert "syslog" in parser.supported_formats
        assert "json" in parser.supported_formats
        assert "csv" in parser.supported_formats

    def test_parse_syslog_line(self):
        """Test parsing a syslog line."""
        parser = LogParser()
        line = "Jan 26 08:15:22 webserver sshd[12345]: Failed password for admin from 192.168.1.105 port 52431 ssh2"

        entry = parser._parse_syslog_line(line)

        assert entry is not None
        assert entry.hostname == "webserver"
        assert entry.process == "sshd"
        assert "Failed password" in entry.message
        assert entry.source_ip == "192.168.1.105"

    def test_parse_syslog_file(self):
        """Test parsing a syslog format file."""
        content = """Jan 26 08:15:22 server sshd[1234]: Failed password for user1
Jan 26 08:15:25 server sshd[1235]: Failed password for user2
Jan 26 08:15:28 server sshd[1236]: Accepted password for user3"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(content)
            f.flush()

            parser = LogParser()
            entries = parser.parse_syslog(f.name)

            assert len(entries) == 3
            assert entries[0].process == "sshd"

    def test_parse_json_file(self):
        """Test parsing a JSON format file."""
        content = [
            {"timestamp": "2026-01-26T10:00:00Z", "source_ip": "192.168.1.1", "message": "Event 1"},
            {"timestamp": "2026-01-26T10:00:01Z", "source_ip": "192.168.1.2", "message": "Event 2"},
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(content, f)
            f.flush()

            parser = LogParser()
            entries = parser.parse_json(f.name)

            assert len(entries) == 2
            assert entries[0].source_ip == "192.168.1.1"

    def test_parse_json_lines(self):
        """Test parsing JSON Lines format."""
        content = """{"timestamp": "2026-01-26T10:00:00Z", "message": "Event 1"}
{"timestamp": "2026-01-26T10:00:01Z", "message": "Event 2"}"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(content)
            f.flush()

            parser = LogParser()
            entries = parser.parse_json(f.name)

            assert len(entries) == 2

    def test_parse_csv_file(self):
        """Test parsing a CSV format file."""
        content = """timestamp,source_ip,message,event_type
2026-01-26 10:00:00,192.168.1.1,Login failed,authentication_failure
2026-01-26 10:00:01,192.168.1.2,Login success,authentication_success"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(content)
            f.flush()

            parser = LogParser()
            entries = parser.parse_csv(f.name)

            assert len(entries) == 2
            assert entries[0].source_ip == "192.168.1.1"
            assert entries[0].event_type == "authentication_failure"

    def test_detect_format_json(self):
        """Test format detection for JSON files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"message": "test"}')
            f.flush()

            parser = LogParser()
            format_type = parser._detect_format(Path(f.name))
            assert format_type == "json"

    def test_detect_format_csv(self):
        """Test format detection for CSV files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("col1,col2,col3\n1,2,3")
            f.flush()

            parser = LogParser()
            format_type = parser._detect_format(Path(f.name))
            assert format_type == "csv"

    def test_extract_ips(self):
        """Test IP address extraction."""
        parser = LogParser()

        source, dest = parser._extract_ips("Connection from 192.168.1.100 to 10.0.0.1")
        assert source == "192.168.1.100"
        assert dest == "10.0.0.1"

        source, dest = parser._extract_ips("No IPs here")
        assert source is None
        assert dest is None

    def test_extract_user(self):
        """Test username extraction."""
        parser = LogParser()

        user = parser._extract_user("Failed password for user john")
        assert user == "john"

        user = parser._extract_user("user=admin logged in")
        assert user == "admin"

    def test_detect_event_type(self):
        """Test event type detection."""
        parser = LogParser()

        event_type = parser._detect_event_type("Failed password attempt")
        assert event_type == "authentication_failure"

        event_type = parser._detect_event_type("Accepted login for user")
        assert event_type == "authentication_success"

        event_type = parser._detect_event_type("sudo command executed")
        assert event_type == "sudo_command"

    def test_file_not_found(self):
        """Test error handling for missing files."""
        parser = LogParser()

        with pytest.raises(FileNotFoundError):
            parser.parse_file("/nonexistent/file.log")

    def test_empty_file(self):
        """Test handling of empty files."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write("")
            f.flush()

            parser = LogParser()
            entries = parser.parse_file(f.name)
            assert len(entries) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
