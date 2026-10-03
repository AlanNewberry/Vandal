"""Tests for vandal.py"""

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch
import pytest
import requests

# Ensure the module is importable
sys.path.insert(0, os.path.dirname(__file__))

import vandal


# ---------------------------------------------------------------------------
# flatten_params
# ---------------------------------------------------------------------------

class TestFlattenParams:
    def test_basic(self):
        assert vandal.flatten_params({"id": ["1"], "q": ["hello"]}) == {"id": "1", "q": "hello"}

    def test_empty(self):
        assert vandal.flatten_params({}) == {}

    def test_multi_value_takes_first(self):
        result = vandal.flatten_params({"id": ["1", "2", "3"]})
        assert result == {"id": "1"}

    def test_already_flat(self):
        result = vandal.flatten_params({"id": "5"})
        assert result == {"id": "5"}


# ---------------------------------------------------------------------------
# is_sql_error
# ---------------------------------------------------------------------------

class TestIsSqlError:
    def test_mysql_error(self):
        assert vandal.is_sql_error("You have an error in your SQL syntax near 'x'")

    def test_pg_error(self):
        assert vandal.is_sql_error("ERROR: syntax error at or near \"'\"")

    def test_sqlite(self):
        assert vandal.is_sql_error("sqlite3::error something broke")

    def test_clean_html(self):
        assert not vandal.is_sql_error("<html><body>Hello world</body></html>")

    def test_empty(self):
        assert not vandal.is_sql_error("")

    def test_case_insensitive(self):
        assert vandal.is_sql_error("WARNING: MYSQL something")


# ---------------------------------------------------------------------------
# is_valid_url
# ---------------------------------------------------------------------------

class TestIsValidUrl:
    def test_http(self):
        assert vandal.is_valid_url("http://example.com")

    def test_https(self):
        assert vandal.is_valid_url("https://example.com/page?id=1")

    def test_invalid(self):
        assert not vandal.is_valid_url("ftp://x.com")

    def test_too_short(self):
        assert not vandal.is_valid_url("http://")


# ---------------------------------------------------------------------------
# check_waf
# ---------------------------------------------------------------------------

class TestCheckWaf:
    def test_403_triggers(self):
        resp = MagicMock()
        resp.status_code = 403
        vandal._waf_warned = False
        assert vandal.check_waf(resp, quiet=True) is True

    def test_429_triggers(self):
        resp = MagicMock()
        resp.status_code = 429
        vandal._waf_warned = False
        assert vandal.check_waf(resp, quiet=True) is True

    def test_200_ok(self):
        resp = MagicMock()
        resp.status_code = 200
        assert vandal.check_waf(resp, quiet=True) is False


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------

class TestArgparse:
    def test_single_url(self):
        parser = vandal.build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.urls == ["http://example.com"]
        assert args.full is False
        assert args.quiet is False
        assert args.delay == 0.01

    def test_full_mode(self):
        parser = vandal.build_parser()
        args = parser.parse_args(["http://example.com", "--full"])
        assert args.full is True

    def test_user_agent(self):
        parser = vandal.build_parser()
        args = parser.parse_args(["http://x.com", "--user-agent", "Bot/1.0"])
        assert args.user_agent == "Bot/1.0"

    def test_output_flag(self):
        parser = vandal.build_parser()
        args = parser.parse_args(["http://x.com", "-o", "out.json"])
        assert args.output == "out.json"

    def test_quiet_flag(self):
        parser = vandal.build_parser()
        args = parser.parse_args(["http://x.com", "-q"])
        assert args.quiet is True

    def test_delay(self):
        parser = vandal.build_parser()
        args = parser.parse_args(["http://x.com", "--delay", "0.5"])
        assert args.delay == 0.5

    def test_multiple_urls(self):
        parser = vandal.build_parser()
        args = parser.parse_args(["http://a.com", "http://b.com"])
        assert len(args.urls) == 2


# ---------------------------------------------------------------------------
# Security headers check
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    def test_all_missing(self):
        resp = MagicMock()
        resp.headers = {}
        session = MagicMock()
        session.get.return_value = resp
        findings = vandal.check_security_headers("http://example.com", session)
        assert len(findings) == 7
        header_names = {f["header"] for f in findings}
        assert "Content-Security-Policy" in header_names
        assert "X-Frame-Options" in header_names
        assert "Permissions-Policy" in header_names

    def test_all_present(self):
        resp = MagicMock()
        resp.headers = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "geolocation=()",
        }
        session = MagicMock()
        session.get.return_value = resp
        findings = vandal.check_security_headers("http://example.com", session)
        assert len(findings) == 0

    def test_partial_missing(self):
        resp = MagicMock()
        resp.headers = {"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'"}
        session = MagicMock()
        session.get.return_value = resp
        findings = vandal.check_security_headers("http://example.com", session)
        assert len(findings) == 5

    def test_severity_levels(self):
        resp = MagicMock()
        resp.headers = {}
        session = MagicMock()
        session.get.return_value = resp
        findings = vandal.check_security_headers("http://example.com", session)
        severities = {f["header"]: f["severity"] for f in findings}
        assert severities["Content-Security-Policy"] == "HIGH"
        assert severities["X-Content-Type-Options"] == "MEDIUM"
        assert severities["Referrer-Policy"] == "LOW"


# ---------------------------------------------------------------------------
# payload_scan with mocked responses
# ---------------------------------------------------------------------------

class TestPayloadScan:
    def _make_session(self):
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "safe page"
        session.get.return_value = resp
        session.post.return_value = resp
        return session

    def test_no_findings_clean_response(self):
        session = self._make_session()
        findings = vandal.payload_scan(
            "http://example.com?id=1",
            session,
            vandal.ADV_XSS_PAYLOADS[:2],
            vandal.xss_check,
            "XSS",
            method="GET", mode="fast", quiet=True,
        )
        assert findings == []

    def test_xss_reflected(self):
        session = MagicMock()
        payload = vandal.ADV_XSS_PAYLOADS[0]
        resp = MagicMock()
        resp.status_code = 200
        resp.text = f"<html>{payload}</html>"
        session.get.return_value = resp
        findings = vandal.payload_scan(
            "http://example.com?q=test",
            session,
            [payload],
            vandal.xss_check,
            "XSS",
            method="GET", mode="fast", quiet=True,
            max_phase_seconds=30, delay=0,
        )
        assert len(findings) >= 1
        assert findings[0]["type"] == "xss"
        assert findings[0]["severity"] == "MEDIUM"

    def test_sqli_error_based(self):
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "you have an error in your sql syntax"
        session.get.return_value = resp
        findings = vandal.payload_scan(
            "http://example.com?id=1",
            session,
            vandal.ADV_SQL_PAYLOADS[:1],
            vandal.sqli_check,
            "SQLi",
            method="GET", mode="fast", quiet=True,
            max_phase_seconds=30, delay=0,
        )
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    def test_post_mode(self):
        session = self._make_session()
        findings = vandal.payload_scan(
            "http://example.com",
            session,
            vandal.ADV_SQL_PAYLOADS[:1],
            vandal.sqli_check,
            "SQLi",
            method="POST", mode="fast", quiet=True,
            max_phase_seconds=30, delay=0,
        )
        assert session.post.called

    def test_waf_backoff(self):
        session = MagicMock()
        resp = MagicMock()
        resp.status_code = 403
        session.get.return_value = resp
        vandal._waf_warned = False
        findings = vandal.payload_scan(
            "http://example.com?id=1",
            session,
            vandal.ADV_XSS_PAYLOADS[:1],
            vandal.xss_check,
            "XSS",
            method="GET", mode="fast", quiet=True,
            max_phase_seconds=30, delay=0,
        )
        # WAF detected means no findings added
        assert findings == []


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

class TestJsonOutput:
    def test_write_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            findings = [{"type": "xss", "severity": "MEDIUM", "url": "http://x.com"}]
            vandal.write_json_output(path, ["http://x.com"], findings)
            with open(path) as f:
                data = json.load(f)
            assert data["tool"] == "vandal"
            assert data["version"] == vandal.__version__
            assert data["total_findings"] == 1
            assert len(data["findings"]) == 1
            assert "timestamp" in data
            assert data["targets"] == ["http://x.com"]
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Destructive payloads removed
# ---------------------------------------------------------------------------

class TestPayloadSafety:
    def test_no_drop_table(self):
        all_payloads = vandal.ADV_SQL_PAYLOADS + vandal.ADV_XSS_PAYLOADS
        for p in all_payloads:
            assert "DROP TABLE" not in p
            assert "shutdown" not in p.lower()

    def test_no_cia_iframe(self):
        for p in vandal.ADV_XSS_PAYLOADS:
            assert "cia.gov" not in p.lower()


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

class TestVersion:
    def test_version_set(self):
        assert vandal.__version__ == "1.0.0"


# ---------------------------------------------------------------------------
# make_session
# ---------------------------------------------------------------------------

class TestMakeSession:
    def test_custom_ua(self):
        s = vandal.make_session("TestBot/1.0")
        assert s.headers["User-Agent"] == "TestBot/1.0"

    def test_default_ua(self):
        s = vandal.make_session()
        assert "User-Agent" not in s.headers or s.headers.get("User-Agent") != ""
