"""
tests/test_patcher.py — unit tests for core.patcher

Tests verify:
  - compute_patch() produces the correct patched lines
  - apply_patch() writes the fix to disk correctly
  - import os is injected when missing
  - .env.example is updated with the variable name
  - SQL rewriting produces valid parameterised calls
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core.detector import Finding
from core.patcher import compute_patch, apply_patch, PatchResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path: Path, src: str, name: str = "target.py") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


def _secret_finding(path: Path, line: int, label: str = "Hardcoded Secret (generic)") -> Finding:
    return Finding(
        file=str(path),
        line=line,
        vuln_type=f"Hardcoded Secret ({label})",
        snippet="",
        remediation="",
    )


def _sql_finding(path: Path, line: int) -> Finding:
    return Finding(
        file=str(path),
        line=line,
        vuln_type="Unparameterised SQL",
        snippet="",
        remediation="",
    )


# ===========================================================================
# Secret patching
# ===========================================================================

class TestSecretPatch:

    def test_basic_replacement(self, tmp_path):
        p = _write(tmp_path, 'api_token = "supersecrettoken1234"\n')
        finding = _secret_finding(p, 1)
        result = compute_patch(finding, project_root=tmp_path)

        assert result is not None
        assert len(result.patched_lines) == 1
        line = result.patched_lines[0]
        assert "os.getenv(" in line
        assert "API_TOKEN" in line
        # Must NOT contain the literal secret
        assert "supersecrettoken1234" not in line

    def test_var_name_uppercased_in_getenv(self, tmp_path):
        p = _write(tmp_path, 'my_api_key = "somevalue123"\n')
        finding = _secret_finding(p, 1)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "os.getenv('MY_API_KEY')" in result.patched_lines[0]

    def test_import_os_injected_when_missing(self, tmp_path):
        p = _write(tmp_path, 'api_key = "topsecret_value"\n')
        finding = _secret_finding(p, 1)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "__import_os__" in result.extra_files

    def test_import_os_not_duplicated(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import os
            api_key = "topsecret_value"
        """))
        finding = _secret_finding(p, 2)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "__import_os__" not in result.extra_files

    def test_env_example_entry_added(self, tmp_path):
        p = _write(tmp_path, 'password = "hunter2_super_secure"\n')
        finding = _secret_finding(p, 1)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "__env_example__" in result.extra_files
        assert "PASSWORD=" in result.extra_files.get("__env_key__", "")

    def test_apply_writes_getenv(self, tmp_path):
        p = _write(tmp_path, 'api_token = "supersecrettoken1234"\n')
        finding = _secret_finding(p, 1)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        apply_patch(result)
        content = p.read_text()
        assert "os.getenv(" in content
        assert "supersecrettoken1234" not in content

    def test_apply_injects_import_os(self, tmp_path):
        p = _write(tmp_path, 'api_token = "supersecrettoken1234"\n')
        finding = _secret_finding(p, 1)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        apply_patch(result)
        content = p.read_text()
        assert "import os" in content

    def test_apply_updates_env_example(self, tmp_path):
        p = _write(tmp_path, 'api_token = "supersecrettoken1234"\n')
        finding = _secret_finding(p, 1)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        apply_patch(result)
        env_file = tmp_path / ".env.example"
        assert env_file.exists()
        assert "API_TOKEN=" in env_file.read_text()

    def test_env_example_not_duplicated(self, tmp_path):
        """Running patch twice should not add the same key twice."""
        p = _write(tmp_path, 'api_token = "supersecrettoken1234"\n')
        env_file = tmp_path / ".env.example"
        env_file.write_text("API_TOKEN=\n")
        finding = _secret_finding(p, 1)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        # __env_example__ should be absent since the key already exists
        assert "__env_example__" not in result.extra_files

    def test_indented_assignment_preserved(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            class Cfg:
                secret = "hardcoded_secret_val"
        """))
        finding = _secret_finding(p, 2)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        patched = result.patched_lines[0]
        assert patched.startswith("    ")  # indentation preserved
        assert "os.getenv(" in patched

    def test_returns_none_for_non_matching_line(self, tmp_path):
        p = _write(tmp_path, 'x = some_function()\n')
        finding = _secret_finding(p, 1)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is None


# ===========================================================================
# SQL patching
# ===========================================================================

class TestSQLPatch:

    def test_fstring_rewritten(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(uid):
                c.execute(f"SELECT * FROM users WHERE id = {uid}")
        """))
        finding = _sql_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        line = result.patched_lines[0]
        # Must use parameterised form — %s appears inside the SQL string
        assert "%s" in line
        assert "(uid,)" in line or "(uid)" in line
        # Must not contain an f-string execute call
        assert "execute(f" not in line

    def test_percent_format_rewritten(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(email, uid):
                c.execute("UPDATE t SET e='%s' WHERE id=%s" % (email, uid))
        """))
        finding = _sql_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        line = result.patched_lines[0]
        assert "email" in line
        assert "uid" in line
        # No longer uses % operator
        assert " % " not in line

    def test_format_method_rewritten(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(status):
                c.execute("SELECT * FROM orders WHERE status='{}'".format(status))
        """))
        finding = _sql_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        line = result.patched_lines[0]
        assert "status" in line
        assert ".format(" not in line

    def test_indentation_preserved(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(uid):
                if uid:
                    c.execute(f"SELECT 1 WHERE id={uid}")
        """))
        finding = _sql_finding(p, 5)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert result.patched_lines[0].startswith("        ")  # 8 spaces

    def test_apply_sql_patch_writes_file(self, tmp_path):
        src = textwrap.dedent("""\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(uid):
                c.execute(f"SELECT * FROM users WHERE id = {uid}")
        """)
        p = _write(tmp_path, src)
        finding = _sql_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        apply_patch(result)
        content = p.read_text()
        # f-string must be gone
        assert 'f"' not in content or "execute(f" not in content
        assert ".execute(" in content

    def test_multiline_execute_collapsed(self, tmp_path):
        """Multi-line execute() spanning two lines is rewritten to a single line."""
        p = _write(tmp_path, textwrap.dedent("""\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(status):
                c.execute(
                    "SELECT * FROM orders WHERE status='{}'".format(status)
                )
        """))
        finding = _sql_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert len(result.patched_lines) == 1

    def test_returns_none_for_safe_execute(self, tmp_path):
        """Already-safe parameterised calls should return no patch."""
        p = _write(tmp_path, textwrap.dedent("""\
            import sqlite3
            c = sqlite3.connect(':memory:').cursor()
            def q(uid):
                c.execute("SELECT * FROM users WHERE id = ?", (uid,))
        """))
        finding = _sql_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        # compute_patch looks for tainted args; safe call has none → None
        assert result is None

    def test_xss_finding_returns_none(self, tmp_path):
        """XSS findings are not patchable and should return None."""
        p = _write(tmp_path, 'return Markup(name)\n')
        finding = Finding(
            file=str(p),
            line=1,
            vuln_type="Potential XSS Sink",
            snippet="return Markup(name)",
            remediation="",
        )
        result = compute_patch(finding, project_root=tmp_path)
        assert result is None


# ===========================================================================
# Command injection patching (CWE-78)
# ===========================================================================

def _cmd_finding(path: Path, line: int) -> Finding:
    return Finding(
        file=str(path),
        line=line,
        vuln_type="Command Injection (CWE-78)",
        snippet="",
        remediation="",
    )


class TestCommandInjectionPatch:

    def test_fstring_rewritten_to_list(self, tmp_path):
        """F-string command rewritten to a safe list without shell=True."""
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            def ping(host):
                subprocess.run(f"ping -c 1 {host}", shell=True)
        """))
        finding = _cmd_finding(p, 3)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        line = result.patched_lines[0]
        # shell=True must be gone
        assert "shell=True" not in line
        # Should be a list form
        assert "[" in line
        # shlex.quote wraps the variable
        assert "shlex.quote" in line

    def test_concatenation_rewritten(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import os
            def ls(path):
                os.system("ls -la " + path)
        """))
        finding = _cmd_finding(p, 3)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        line = result.patched_lines[0]
        assert "shell=True" not in line
        assert "shlex.quote" in line

    def test_os_system_replaced_with_subprocess_run(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import os
            def ls(path):
                os.system("ls -la " + path)
        """))
        finding = _cmd_finding(p, 3)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "subprocess.run" in result.patched_lines[0]

    def test_shell_true_literal_rewritten(self, tmp_path):
        """subprocess.run("literal", shell=True) → subprocess.run(['literal'], no shell)."""
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            subprocess.run("ls -la", shell=True)
        """))
        finding = _cmd_finding(p, 2)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        line = result.patched_lines[0]
        assert "shell=True" not in line
        assert "[" in line

    def test_shlex_import_injected_when_missing(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            def ping(host):
                subprocess.run(f"ping {host}", shell=True)
        """))
        finding = _cmd_finding(p, 3)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "__import_shlex__" in result.extra_files

    def test_shlex_import_not_duplicated(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import shlex
            import subprocess
            def ping(host):
                subprocess.run(f"ping {host}", shell=True)
        """))
        finding = _cmd_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "__import_shlex__" not in result.extra_files

    def test_apply_cmd_patch_writes_file(self, tmp_path):
        src = textwrap.dedent("""\
            import subprocess
            def ping(host):
                subprocess.run(f"ping -c 1 {host}", shell=True)
        """)
        p = _write(tmp_path, src)
        finding = _cmd_finding(p, 3)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        apply_patch(result)
        content = p.read_text()
        assert "shell=True" not in content
        assert "shlex" in content

    def test_indentation_preserved(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            import subprocess
            def run(path):
                if path:
                    subprocess.run("ls " + path, shell=True)
        """))
        finding = _cmd_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert result.patched_lines[0].startswith("        ")  # 8 spaces


# ===========================================================================
# Insecure file upload patching (CWE-434/CWE-22)
# ===========================================================================

def _upload_finding(path: Path, line: int) -> Finding:
    return Finding(
        file=str(path),
        line=line,
        vuln_type="Insecure File Upload (CWE-434/CWE-22)",
        snippet="",
        remediation="",
    )


class TestFileUploadPatch:

    def test_raw_save_gets_secure_filename(self, tmp_path):
        """f.save(os.path.join(folder, fname)) → f.save(os.path.join(folder, secure_filename(fname)))."""
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            import os
            def upload():
                f = request.files["upload"]
                f.save(os.path.join("/uploads", f.filename))
        """))
        finding = _upload_finding(p, 5)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        patched = result.patched_lines[0]
        assert "secure_filename" in patched

    def test_todo_comments_inserted(self, tmp_path):
        """Patched output should include TODO comments for extension and MIME checks."""
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            import os
            def upload():
                f = request.files["upload"]
                f.save(os.path.join("/uploads", f.filename))
        """))
        finding = _upload_finding(p, 5)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        patched = result.patched_lines[0]
        assert "TODO" in patched
        assert "MIME" in patched or "extension" in patched.lower()

    def test_secure_filename_import_injected(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            import os
            def upload():
                f = request.files["upload"]
                f.save(os.path.join("/uploads", f.filename))
        """))
        finding = _upload_finding(p, 5)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "__import_secure_filename__" in result.extra_files

    def test_secure_filename_import_not_duplicated(self, tmp_path):
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            from werkzeug.utils import secure_filename
            import os
            def upload():
                f = request.files["upload"]
                f.save(os.path.join("/uploads", f.filename))
        """))
        finding = _upload_finding(p, 6)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "__import_secure_filename__" not in result.extra_files

    def test_apply_upload_patch_writes_file(self, tmp_path):
        src = textwrap.dedent("""\
            from flask import request
            import os
            def upload():
                f = request.files["upload"]
                f.save(os.path.join("/uploads", f.filename))
        """)
        p = _write(tmp_path, src)
        finding = _upload_finding(p, 5)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        apply_patch(result)
        content = p.read_text()
        assert "secure_filename" in content

    def test_plain_save_path_wrapped(self, tmp_path):
        """f.save(fname) → f.save(secure_filename(fname))."""
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            def upload():
                f = request.files["upload"]
                f.save(f.filename)
        """))
        finding = _upload_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is not None
        assert "secure_filename" in result.patched_lines[0]

    def test_returns_none_for_non_save_line(self, tmp_path):
        """Lines that don't match .save() pattern should return None."""
        p = _write(tmp_path, textwrap.dedent("""\
            from flask import request
            def upload():
                f = request.files["upload"]
                print(f.filename)
        """))
        finding = _upload_finding(p, 4)
        result = compute_patch(finding, project_root=tmp_path)
        assert result is None
