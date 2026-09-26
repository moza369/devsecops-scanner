"""
tests/test_detector.py — unit tests for core.detector

Each test writes a tiny Python snippet to a temp file so the detector
exercises real file I/O (matching production behaviour).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core.detector import scan_file, Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, src: str) -> Path:
    """Write *src* to a temp .py file and return its Path."""
    p = tmp_path / "snippet.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


def _vuln_types(findings: list[Finding]) -> list[str]:
    return [f.vuln_type for f in findings]


# ===========================================================================
# SQL injection
# ===========================================================================

class TestSQLDetection:

    def test_fstring_inline(self, tmp_path):
        p = _write(tmp_path, """\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(uid):
                c.execute(f"SELECT * FROM users WHERE id = {uid}")
        """)
        findings = scan_file(p)
        sql_findings = [f for f in findings if "SQL" in f.vuln_type]
        assert len(sql_findings) == 1
        assert sql_findings[0].line == 4

    def test_fstring_variable(self, tmp_path):
        """Tainted variable assigned before execute() should be caught."""
        p = _write(tmp_path, """\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(name):
                sql = f"SELECT * FROM users WHERE name = '{name}'"
                c.execute(sql)
        """)
        findings = scan_file(p)
        sql_findings = [f for f in findings if "SQL" in f.vuln_type]
        assert len(sql_findings) == 1

    def test_percent_format_inline(self, tmp_path):
        p = _write(tmp_path, """\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(email, uid):
                c.execute("UPDATE t SET e='%s' WHERE id=%s" % (email, uid))
        """)
        findings = scan_file(p)
        assert any("SQL" in v for v in _vuln_types(findings))

    def test_format_method(self, tmp_path):
        p = _write(tmp_path, """\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(status):
                c.execute("SELECT * FROM o WHERE status='{}'".format(status))
        """)
        findings = scan_file(p)
        assert any("SQL" in v for v in _vuln_types(findings))

    def test_concatenation_variable(self, tmp_path):
        """String concatenation assigned to variable then executed."""
        p = _write(tmp_path, """\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(rid):
                sql = "DELETE FROM r WHERE id = " + rid
                c.execute(sql)
        """)
        findings = scan_file(p)
        sql_findings = [f for f in findings if "SQL" in f.vuln_type]
        assert len(sql_findings) == 1

    def test_safe_parameterised_not_flagged(self, tmp_path):
        """Parameterised queries must not produce any findings."""
        p = _write(tmp_path, """\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(uid):
                c.execute("SELECT * FROM users WHERE id = ?", (uid,))
        """)
        findings = scan_file(p)
        assert not any("SQL" in v for v in _vuln_types(findings))

    def test_finding_has_remediation(self, tmp_path):
        p = _write(tmp_path, """\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(x):
                c.execute(f"SELECT 1 WHERE a={x}")
        """)
        findings = scan_file(p)
        sql_f = next(f for f in findings if "SQL" in f.vuln_type)
        assert "parameteris" in sql_f.remediation.lower()


# ===========================================================================
# Hardcoded secrets
# ===========================================================================

class TestSecretDetection:

    def test_aws_access_key_id(self, tmp_path):
        p = _write(tmp_path, 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_file(p)
        assert any("AWS Access Key ID" in v for v in _vuln_types(findings))

    def test_aws_secret_access_key(self, tmp_path):
        p = _write(tmp_path,
            'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        )
        findings = scan_file(p)
        assert any("AWS Secret" in v for v in _vuln_types(findings))

    def test_generic_api_token(self, tmp_path):
        p = _write(tmp_path, 'api_token = "super_secret_value_here"\n')
        findings = scan_file(p)
        assert any("Secret" in v for v in _vuln_types(findings))

    def test_generic_password(self, tmp_path):
        p = _write(tmp_path, 'password = "hunter2_secure_pass"\n')
        findings = scan_file(p)
        assert any("Secret" in v for v in _vuln_types(findings))

    def test_short_value_not_flagged(self, tmp_path):
        """Values shorter than 8 chars should not trigger the generic pattern."""
        p = _write(tmp_path, 'token = "tiny"\n')
        findings = scan_file(p)
        assert not any("Secret" in v for v in _vuln_types(findings))

    def test_env_var_usage_not_flagged(self, tmp_path):
        """Reads from os.environ should not be flagged."""
        p = _write(tmp_path, textwrap.dedent("""\
            import os
            api_key = os.environ["API_KEY"]
        """))
        findings = scan_file(p)
        assert not any("Secret" in v for v in _vuln_types(findings))

    def test_secret_snippet_in_finding(self, tmp_path):
        p = _write(tmp_path, 'api_key = "supersecrettoken1234"\n')
        findings = scan_file(p)
        secret_f = next(f for f in findings if "Secret" in f.vuln_type)
        assert "api_key" in secret_f.snippet

    def test_secret_line_number(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            x = 1
            y = 2
            api_token = "topsecretvalue99"
        """))
        findings = scan_file(p)
        secret_f = next(f for f in findings if "Secret" in f.vuln_type)
        assert secret_f.line == 3


# ===========================================================================
# XSS sinks
# ===========================================================================

class TestXSSDetection:

    def test_markup_sink(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import Markup
            def view(name):
                return Markup(f"<b>{name}</b>")
        """))
        findings = scan_file(p)
        assert any("XSS" in v for v in _vuln_types(findings))

    def test_render_template_string_sink(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import render_template_string
            def view(user_input):
                return render_template_string(user_input)
        """))
        findings = scan_file(p)
        assert any("XSS" in v for v in _vuln_types(findings))

    def test_mark_safe_sink(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            from django.utils.safestring import mark_safe
            def view(val):
                return mark_safe(val)
        """))
        findings = scan_file(p)
        assert any("XSS" in v for v in _vuln_types(findings))

    def test_xss_line_number(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            x = 1
            from flask import Markup
            def v(s):
                return Markup(s)
        """))
        findings = scan_file(p)
        xss_f = next(f for f in findings if "XSS" in f.vuln_type)
        assert xss_f.line == 4


# ===========================================================================
# Edge cases
# ===========================================================================

class TestEdgeCases:

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.py"
        p.write_text("", encoding="utf-8")
        assert scan_file(p) == []

    def test_syntax_error_file_falls_back_to_regex(self, tmp_path):
        """A file with a syntax error should still be regex-scanned."""
        p = _write(tmp_path, 'password = "secretpass123"\ndef (\n')
        # Regex should still catch the secret even if AST parse fails
        findings = scan_file(p)
        assert any("Secret" in v for v in _vuln_types(findings))

    def test_multiple_findings_in_one_file(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            api_key = "supersecrettoken9999"
            def q(x):
                c.execute(f"SELECT 1 WHERE a={x}")
        """))
        findings = scan_file(p)
        types = _vuln_types(findings)
        assert any("SQL" in t for t in types)
        assert any("Secret" in t for t in types)

    def test_finding_fields_populated(self, tmp_path):
        p = _write(tmp_path, 'api_token = "mysecretvalue"\n')
        findings = scan_file(p)
        f = findings[0]
        assert f.file == str(p)
        assert f.line > 0
        assert f.snippet
        assert f.remediation


# ===========================================================================
# Command injection (CWE-78)
# ===========================================================================

class TestCommandInjectionDetection:

    def test_subprocess_run_shell_true_fstring(self, tmp_path):
        """subprocess.run with shell=True and f-string must be flagged."""
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            def ping(host):
                subprocess.run(f"ping -c 1 {host}", shell=True)
        """))
        findings = scan_file(p)
        assert any("Command Injection" in f.vuln_type for f in findings)

    def test_subprocess_run_shell_true_literal(self, tmp_path):
        """subprocess.run with shell=True even on a plain string must be flagged."""
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            subprocess.run("ls -la", shell=True)
        """))
        findings = scan_file(p)
        assert any("Command Injection" in f.vuln_type for f in findings)

    def test_subprocess_popen_fstring(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            def compress(fname):
                subprocess.Popen(f"gzip {fname}", shell=True)
        """))
        findings = scan_file(p)
        assert any("Command Injection" in f.vuln_type for f in findings)

    def test_os_system_concatenation(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import os
            def ls(path):
                os.system("ls -la " + path)
        """))
        findings = scan_file(p)
        assert any("Command Injection" in f.vuln_type for f in findings)

    def test_os_popen_percent_format(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import os
            def cat(fp):
                os.popen("cat %s" % fp)
        """))
        findings = scan_file(p)
        assert any("Command Injection" in f.vuln_type for f in findings)

    def test_tainted_variable_passed_to_check_output(self, tmp_path):
        """Tainted variable assigned then used in subprocess must be caught."""
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            def usage(mp):
                cmd = f"df -h {mp}"
                subprocess.check_output(cmd, shell=True)
        """))
        findings = scan_file(p)
        assert any("Command Injection" in f.vuln_type for f in findings)

    def test_safe_list_not_flagged(self, tmp_path):
        """subprocess.run with a list argument and no shell=True must NOT be flagged."""
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            def ping(host):
                subprocess.run(["ping", "-c", "1", host])
        """))
        findings = scan_file(p)
        assert not any("Command Injection" in f.vuln_type for f in findings)

    def test_line_number_reported(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            x = 1
            y = 2
            subprocess.run(f"echo {x}", shell=True)
        """))
        findings = scan_file(p)
        cmd_f = next(f for f in findings if "Command Injection" in f.vuln_type)
        assert cmd_f.line == 4

    def test_remediation_mentions_list(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            subprocess.run("ls", shell=True)
        """))
        findings = scan_file(p)
        cmd_f = next(f for f in findings if "Command Injection" in f.vuln_type)
        assert "list" in cmd_f.remediation.lower()


# ===========================================================================
# Insecure file upload / path traversal (CWE-434 / CWE-22) — Python
# ===========================================================================

class TestFileUploadDetectionPython:

    def test_raw_save_without_secure_filename(self, tmp_path):
        """file.save() on a request.files object without secure_filename must be flagged."""
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            import os
            def upload():
                f = request.files["upload"]
                f.save(os.path.join("/uploads", f.filename))
        """))
        findings = scan_file(p)
        assert any("File Upload" in f.vuln_type for f in findings)

    def test_raw_save_via_files_get(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            import os
            def upload():
                upload = request.files.get("upload")
                upload.save(os.path.join("/uploads", upload.filename))
        """))
        findings = scan_file(p)
        assert any("File Upload" in f.vuln_type for f in findings)

    def test_secure_filename_not_flagged(self, tmp_path):
        """If secure_filename() wraps the save path the call must NOT be flagged."""
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            from werkzeug.utils import secure_filename
            import os
            def upload():
                f = request.files["upload"]
                fname = secure_filename(f.filename)
                f.save(os.path.join("/uploads", fname))
        """))
        findings = scan_file(p)
        assert not any("File Upload" in f.vuln_type for f in findings)

    def test_weak_extension_check_flagged(self, tmp_path):
        """Extension-only check via .rsplit() without secure_filename must be flagged."""
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            import os
            def upload():
                f = request.files["file"]
                fname = f.filename
                if fname.rsplit(".", 1)[-1].lower() in {"jpg", "png"}:
                    f.save(os.path.join("/uploads", fname))
        """))
        findings = scan_file(p)
        assert any("File Upload" in f.vuln_type for f in findings)

    def test_remediation_mentions_secure_filename(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            import os
            def upload():
                f = request.files["upload"]
                f.save(os.path.join("/uploads", f.filename))
        """))
        findings = scan_file(p)
        fu_f = next(f for f in findings if "File Upload" in f.vuln_type)
        assert "secure_filename" in fu_f.remediation


# ===========================================================================
# Insecure file upload (CWE-434 / CWE-22) — PHP
# ===========================================================================

class TestFileUploadDetectionPHP:

    def _write_php(self, tmp_path: Path, src: str) -> Path:
        p = tmp_path / "upload.php"
        p.write_text(textwrap.dedent(src), encoding="utf-8")
        return p

    def test_bare_files_no_mime_no_whitelist(self, tmp_path):
        p = self._write_php(tmp_path, """\
            <?php
            move_uploaded_file($_FILES["upload"]["tmp_name"], "/var/uploads/" . $_FILES["upload"]["name"]);
        """)
        findings = scan_file(p)
        assert any("File Upload" in f.vuln_type for f in findings)

    def test_files_with_mime_check_not_flagged(self, tmp_path):
        """$_FILES access accompanied by finfo_open should NOT be flagged."""
        p = self._write_php(tmp_path, """\
            <?php
            $allowed = ["image/jpeg", "image/png"];
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime  = finfo_file($finfo, $_FILES["upload"]["tmp_name"]);
            if (in_array($mime, $allowed)) {
                move_uploaded_file($_FILES["upload"]["tmp_name"], "/safe/" . basename($_FILES["upload"]["name"]));
            }
        """)
        findings = scan_file(p)
        assert not any("File Upload" in f.vuln_type for f in findings)

    def test_php_finding_has_remediation(self, tmp_path):
        p = self._write_php(tmp_path, """\
            <?php
            move_uploaded_file($_FILES["f"]["tmp_name"], "/uploads/" . $_FILES["f"]["name"]);
        """)
        findings = scan_file(p)
        fu_f = next(f for f in findings if "File Upload" in f.vuln_type)
        assert "finfo" in fu_f.remediation or "mime" in fu_f.remediation.lower()

    def test_php_line_number(self, tmp_path):
        p = self._write_php(tmp_path, """\
            <?php
            // line 2 is a comment
            $name = $_FILES["upload"]["name"];
        """)
        findings = scan_file(p)
        assert any(f.line == 3 for f in findings if "File Upload" in f.vuln_type)
