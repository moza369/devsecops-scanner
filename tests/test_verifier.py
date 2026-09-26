"""
tests/test_verifier.py — unit tests for core.verifier

Tests cover:
  - Clean file (no vulnerabilities, valid syntax) → clean=True.
  - Syntax-broken file → syntax_ok=False, scan skipped.
  - Partially patched file (vulnerability remains) → clean=False, findings non-empty.
  - Missing/unreadable file → handled gracefully.
  - SQL injection vulnerability confirmed eliminated after patch.
  - Hardcoded secret confirmed eliminated after patch.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core.verifier import verify_remediation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, src: str, name: str = "snippet.py") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


# ===========================================================================
# Clean file
# ===========================================================================

class TestVerifyCleanFile:

    def test_clean_file_is_clean(self, tmp_path):
        p = _write(tmp_path, """\
            import os

            def get_user(conn, uid):
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
                return cursor.fetchone()
        """)
        result = verify_remediation(p)
        assert result["syntax_ok"] is True
        assert result["syntax_error"] is None
        assert result["findings"] == []
        assert result["clean"] is True

    def test_empty_file_is_clean(self, tmp_path):
        p = _write(tmp_path, "")
        result = verify_remediation(p)
        assert result["syntax_ok"] is True
        assert result["clean"] is True

    def test_comment_only_file_is_clean(self, tmp_path):
        p = _write(tmp_path, """\
            # This file intentionally left blank.
            # No vulnerabilities here.
        """)
        result = verify_remediation(p)
        assert result["syntax_ok"] is True
        assert result["clean"] is True


# ===========================================================================
# Syntax-broken file
# ===========================================================================

class TestVerifySyntaxBroken:

    def test_syntax_error_sets_flag(self, tmp_path):
        p = _write(tmp_path, """\
            def broken(:
                pass
        """)
        result = verify_remediation(p)
        assert result["syntax_ok"] is False

    def test_syntax_error_message_is_present(self, tmp_path):
        p = _write(tmp_path, "x = (1 +\n")
        result = verify_remediation(p)
        assert result["syntax_ok"] is False
        assert result["syntax_error"] is not None
        assert len(result["syntax_error"]) > 0

    def test_syntax_error_skips_scan(self, tmp_path):
        """When syntax is broken the findings list should be empty (scan skipped)."""
        p = _write(tmp_path, "def f(:\n    pass\n")
        result = verify_remediation(p)
        assert result["syntax_ok"] is False
        assert result["findings"] == []

    def test_clean_false_on_syntax_error(self, tmp_path):
        p = _write(tmp_path, "class :\n    pass\n")
        result = verify_remediation(p)
        assert result["clean"] is False


# ===========================================================================
# Partially patched / vulnerability still present
# ===========================================================================

class TestVerifyPartialPatch:

    def test_sql_vuln_still_present(self, tmp_path):
        """A file that still has an unparameterised SQL query is not clean."""
        p = _write(tmp_path, """\
            import sqlite3

            def get_user(conn, uid):
                cursor = conn.cursor()
                cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
                return cursor.fetchone()
        """)
        result = verify_remediation(p)
        assert result["syntax_ok"] is True
        assert result["clean"] is False
        sql_findings = [f for f in result["findings"] if "SQL" in f.vuln_type]
        assert len(sql_findings) >= 1

    def test_hardcoded_secret_still_present(self, tmp_path):
        """A file with a hardcoded API key reports clean=False."""
        p = _write(tmp_path, """\
            api_key = "super_secret_key_12345"

            def connect():
                pass
        """)
        result = verify_remediation(p)
        assert result["syntax_ok"] is True
        assert result["clean"] is False
        secret_findings = [f for f in result["findings"] if "Secret" in f.vuln_type]
        assert len(secret_findings) >= 1

    def test_findings_list_populated(self, tmp_path):
        """findings should contain Finding objects with expected attributes."""
        p = _write(tmp_path, """\
            token = "ghp_abcdefghijklmnopqrstuvwxyz123456"

            def do_work():
                pass
        """)
        result = verify_remediation(p)
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert hasattr(finding, "file")
        assert hasattr(finding, "line")
        assert hasattr(finding, "vuln_type")


# ===========================================================================
# Vulnerability eliminated after patch
# ===========================================================================

class TestVerifySuccessfulRemediation:

    def test_sql_eliminated_by_parameterisation(self, tmp_path):
        """After parameterising the query the verifier should find it clean."""
        p = _write(tmp_path, """\
            import sqlite3

            def get_user(conn, uid):
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
                return cursor.fetchone()
        """)
        result = verify_remediation(p)
        assert result["clean"] is True
        sql_findings = [f for f in result["findings"] if "SQL" in f.vuln_type]
        assert sql_findings == []

    def test_secret_eliminated_by_env_var(self, tmp_path):
        """After replacing the literal with os.getenv() the verifier is clean."""
        p = _write(tmp_path, """\
            import os

            api_key = os.getenv("API_KEY")

            def connect():
                pass
        """)
        result = verify_remediation(p)
        assert result["clean"] is True
        secret_findings = [f for f in result["findings"] if "Secret" in f.vuln_type]
        assert secret_findings == []


# ===========================================================================
# Unreadable / missing file
# ===========================================================================

class TestVerifyMissingFile:

    def test_missing_file_returns_syntax_error(self, tmp_path):
        ghost = tmp_path / "nonexistent.py"
        result = verify_remediation(ghost)
        assert result["syntax_ok"] is False
        assert result["syntax_error"] is not None
        assert "Cannot read file" in result["syntax_error"]

    def test_missing_file_clean_is_false(self, tmp_path):
        ghost = tmp_path / "nonexistent.py"
        result = verify_remediation(ghost)
        assert result["clean"] is False
