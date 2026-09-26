"""
detector.py — static analysis engine.

Detects:
  - Unparameterised SQL queries (string concatenation / f-string injection)
  - Potential XSS sinks (Flask/Django response helpers with raw user input)
  - Hardcoded API tokens / secrets (AWS keys, generic high-entropy tokens, etc.)
  - Command injection (CWE-78): subprocess/os calls with shell=True or tainted args
  - Insecure file upload / path traversal (CWE-434 / CWE-22): missing secure_filename,
    weak extension checks, unvalidated $_FILES handling in PHP
"""

from __future__ import annotations

import ast
import os
import re
import tokenize
import io
from pathlib import Path
from typing import List

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    file: str
    line: int
    vuln_type: str
    snippet: str
    remediation: str


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Unparameterised SQL: detects string formatting / concatenation used inside
# common SQL execution calls.
_SQL_EXEC_RE = re.compile(
    r"""(?:execute|cursor\.execute|db\.execute|conn\.execute)\s*\(\s*"""
    r"""(?:f["']|["'][^"']*(?:\+|%|\.format))""",
    re.IGNORECASE,
)

# XSS sinks: raw HTML response helpers that may echo user input.
_XSS_SINK_RE = re.compile(
    r"""(?:render_template_string|Markup|mark_safe|HttpResponse|Response)\s*\(""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# CWE-78 — Command injection (Python, regex pre-filter)
# ---------------------------------------------------------------------------

# Detects subprocess.run/Popen/call or os.system/popen where the first
# argument is built from string formatting/concatenation, OR where
# shell=True appears.  The AST visitor does the precise taint check;
# this regex is only used as a quick line-level pre-filter.
_CMD_CALL_RE = re.compile(
    r"""(?:subprocess\.(?:run|Popen|call|check_output|check_call)|os\.(?:system|popen))\s*\(""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# CWE-434 / CWE-22 — Insecure file upload / path traversal (Python regex)
# ---------------------------------------------------------------------------

# Detects file.save() without secure_filename on the same or adjacent line.
_FILE_SAVE_RE = re.compile(r"""\.save\s*\(""")

# Detects weak extension-only whitelist patterns (e.g. endswith / rsplit checks
# without MIME validation).
_WEAK_EXT_RE = re.compile(
    r"""filename\s*\.(?:endswith|rsplit|split)\s*\(""",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# CWE-434 / CWE-22 — Insecure file upload (PHP regex)
# ---------------------------------------------------------------------------

# Flags bare $_FILES access that is not followed by mime_content_type / finfo
# or an explicit whitelist — detected via absence patterns handled in scan_file.
_PHP_FILES_RE = re.compile(r"""\$_FILES\s*\[""")
_PHP_MIME_CHECK_RE = re.compile(
    r"""(?:mime_content_type|finfo_open|finfo_file|getimagesize)\s*\(""",
    re.IGNORECASE,
)

# Hardcoded secrets: AWS key IDs, generic "key/secret/token/password" assignments.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "AWS Access Key ID",
        re.compile(r"""(?:^|[\s'"])AKIA[0-9A-Z]{16}(?:[\s'"]|$)"""),
    ),
    (
        "AWS Secret Access Key",
        re.compile(
            r"""(?:aws_secret|secret_access_key)\s*=\s*['"][A-Za-z0-9/+]{40}['"]""",
            re.IGNORECASE,
        ),
    ),
    (
        "Hardcoded secret/token/password",
        re.compile(
            r"""(?:api_key|api_token|secret|password|passwd|token)\s*=\s*['"][^'"]{8,}['"]""",
            re.IGNORECASE,
        ),
    ),
]


# ---------------------------------------------------------------------------
# AST-based SQL detection
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# AST-based command injection detection (CWE-78)
# ---------------------------------------------------------------------------

#: Subprocess / os functions whose first argument may be a shell command.
_CMD_FUNCS: set[tuple[str, str]] = {
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("os", "system"),
    ("os", "popen"),
}


class _CmdInjectionVisitor(ast.NodeVisitor):
    """Walk the AST looking for subprocess / os calls that either:
    * pass a tainted (f-string / concat / format) first argument, OR
    * use ``shell=True``.
    """

    def __init__(self, source_lines: list[str], filename: str) -> None:
        self._lines = source_lines
        self._filename = filename
        self.findings: list[Finding] = []
        self._tainted: dict[str, ast.AST] = {}

    def _record(self, node: ast.AST, reason: str) -> None:
        line_no = getattr(node, "lineno", 0)
        snippet = self._lines[line_no - 1].strip() if line_no else ""
        self.findings.append(
            Finding(
                file=self._filename,
                line=line_no,
                vuln_type="Command Injection (CWE-78)",
                snippet=snippet,
                remediation=(
                    "Pass commands as a list instead of a shell string and avoid "
                    "shell=True. Use shlex.quote() if a shell string is unavoidable."
                ),
            )
        )

    def _is_tainted(self, node: ast.expr) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            return True
        if isinstance(node, ast.Name) and node.id in self._tainted:
            return True
        return False

    def _has_shell_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _is_cmd_call(self, node: ast.Call) -> bool:
        """Return True if *node* calls one of the known dangerous functions."""
        func = node.func
        # subprocess.run(…) / os.system(…) style
        if isinstance(func, ast.Attribute):
            method = func.attr
            if isinstance(func.value, ast.Name):
                module = func.value.id
                return (module, method) in _CMD_FUNCS
            # Could also be a chained attribute — skip for now
        # Direct name: system("…") after `from os import system`
        if isinstance(func, ast.Name):
            return func.id in {m for _, m in _CMD_FUNCS}
        return False

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        if self._is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted[target.id] = node
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if self._is_cmd_call(node):
            shell_true = self._has_shell_true(node)
            tainted_arg = node.args and self._is_tainted(node.args[0])
            if shell_true or tainted_arg:
                reason = "shell=True" if shell_true else "tainted argument"
                self._record(node, reason)
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# AST-based insecure file upload detection (CWE-434 / CWE-22, Python)
# ---------------------------------------------------------------------------

class _FileUploadVisitor(ast.NodeVisitor):
    """Detect insecure file-upload patterns:
    * file.save() called without secure_filename() in the same scope.
    * Weak extension-only validation (endswith / rsplit on filename) without
      MIME-type inspection.
    """

    def __init__(self, source_lines: list[str], filename: str) -> None:
        self._lines = source_lines
        self._filename = filename
        self.findings: list[Finding] = []
        # Collect names passed through secure_filename() so we can allow them.
        self._secured: set[str] = set()
        # Names that came from request.files[…]
        self._upload_vars: set[str] = set()

    def _record(self, node: ast.AST, detail: str) -> None:
        line_no = getattr(node, "lineno", 0)
        snippet = self._lines[line_no - 1].strip() if line_no else ""
        self.findings.append(
            Finding(
                file=self._filename,
                line=line_no,
                vuln_type="Insecure File Upload (CWE-434/CWE-22)",
                snippet=snippet,
                remediation=(
                    "Use werkzeug.utils.secure_filename() on the uploaded filename, "
                    "validate the extension against a strict whitelist, and inspect "
                    "the MIME type with python-magic or filetype before saving."
                ),
            )
        )

    def _is_secure_filename_call(self, node: ast.expr) -> bool:
        """True if *node* is a call to secure_filename(…)."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "secure_filename"
        )

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        # Track: fname = secure_filename(…)
        if self._is_secure_filename_call(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._secured.add(t.id)
        # Track: f = request.files[…] or f = request.files.get(…)
        val = node.value
        if isinstance(val, ast.Subscript) and isinstance(val.value, ast.Attribute):
            if (
                isinstance(val.value.value, ast.Name)
                and val.value.value.id == "request"
                and val.value.attr == "files"
            ):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self._upload_vars.add(t.id)
        if (
            isinstance(val, ast.Call)
            and isinstance(val.func, ast.Attribute)
            and val.func.attr == "get"
            and isinstance(val.func.value, ast.Attribute)
            and isinstance(val.func.value.value, ast.Name)
            and val.func.value.value.id == "request"
            and val.func.value.attr == "files"
        ):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._upload_vars.add(t.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Detect: <var>.save(path) where var is an upload and path is not secured
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "save"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self._upload_vars
        ):
            # Check if any argument passed to save() is a secured name
            save_args = [ast.unparse(a) for a in node.args]
            all_secured = all(
                any(sec in arg for sec in self._secured)
                for arg in save_args
            )
            if not all_secured or not self._secured:
                self._record(node, "file.save() without secure_filename()")

        self.generic_visit(node)


class _SQLVisitor(ast.NodeVisitor):
    """Walk the AST looking for .execute() calls whose argument is a
    concatenation, f-string, or %-formatted string literal.

    Also tracks simple variable assignments so that patterns like:
        sql = f"SELECT ... {user}"
        cursor.execute(sql)
    are flagged even when the tainted string is stored in a name first.
    """

    def __init__(self, source_lines: list[str], filename: str) -> None:
        self._lines = source_lines
        self._filename = filename
        self.findings: list[Finding] = []
        # Map of variable name → assignment node for taint tracking
        self._tainted: dict[str, ast.AST] = {}

    def _record(self, node: ast.AST, extra: str = "") -> None:
        line_no = getattr(node, "lineno", 0)
        snippet = self._lines[line_no - 1].strip() if line_no else ""
        self.findings.append(
            Finding(
                file=self._filename,
                line=line_no,
                vuln_type="Unparameterised SQL",
                snippet=snippet,
                remediation=(
                    "Use parameterised queries: cursor.execute(sql, (param,)) "
                    "instead of string formatting."
                ),
            )
        )

    def _is_tainted(self, node: ast.expr) -> bool:
        """Return True if *node* is a tainted (unsafe) SQL expression."""
        if isinstance(node, ast.JoinedStr):          # f-string
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if (                                          # "...".format(...)
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            return True
        if isinstance(node, ast.Name) and node.id in self._tainted:
            return True
        return False

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        """Track simple name = <tainted_expr> assignments."""
        if self._is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted[target.id] = node
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Match <anything>.execute(...)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.args
        ):
            arg = node.args[0]
            if self._is_tainted(arg):
                self._record(node)
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_file(path: Path) -> List[Finding]:
    """Scan a single source file (Python or PHP) and return all findings."""
    findings: list[Finding] = []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    lines = source.splitlines()
    filename = str(path)
    suffix = path.suffix.lower()

    if suffix == ".php":
        findings.extend(_scan_php(lines, filename))
        return findings

    # --- AST-based scans (Python only) ---
    try:
        tree = ast.parse(source, filename=filename)

        sql_visitor = _SQLVisitor(lines, filename)
        sql_visitor.visit(tree)
        findings.extend(sql_visitor.findings)

        cmd_visitor = _CmdInjectionVisitor(lines, filename)
        cmd_visitor.visit(tree)
        findings.extend(cmd_visitor.findings)

        upload_visitor = _FileUploadVisitor(lines, filename)
        upload_visitor.visit(tree)
        findings.extend(upload_visitor.findings)

    except SyntaxError:
        pass  # fall through to regex scan only

    # --- Regex line-by-line scans (Python) ---
    for lineno, line in enumerate(lines, start=1):
        # XSS sinks
        if _XSS_SINK_RE.search(line):
            findings.append(
                Finding(
                    file=filename,
                    line=lineno,
                    vuln_type="Potential XSS Sink",
                    snippet=line.strip(),
                    remediation=(
                        "Avoid rendering raw user-controlled data as HTML. "
                        "Use template auto-escaping and sanitise inputs."
                    ),
                )
            )
        # Secrets / hardcoded credentials
        for label, pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        file=filename,
                        line=lineno,
                        vuln_type=f"Hardcoded Secret ({label})",
                        snippet=line.strip(),
                        remediation=(
                            "Remove the credential from source code. "
                            "Load secrets from environment variables or a secrets manager."
                        ),
                    )
                )
                break  # one finding per line per category

        # Weak extension-only upload check (regex fallback for edge cases the
        # AST visitor may miss when the file object is not clearly tracked)
        if _WEAK_EXT_RE.search(line) and _FILE_SAVE_RE.search(source):
            # Only flag if secure_filename is not imported/used in the file
            if "secure_filename" not in source:
                findings.append(
                    Finding(
                        file=filename,
                        line=lineno,
                        vuln_type="Insecure File Upload (CWE-434/CWE-22)",
                        snippet=line.strip(),
                        remediation=(
                            "Use werkzeug.utils.secure_filename() on the uploaded filename, "
                            "validate the extension against a strict whitelist, and inspect "
                            "the MIME type with python-magic or filetype before saving."
                        ),
                    )
                )

    return findings


def _scan_php(lines: list[str], filename: str) -> list[Finding]:
    """PHP-specific line-by-line scan for CWE-434/CWE-22."""
    findings: list[Finding] = []
    source = "\n".join(lines)

    # Check whether the file has any MIME-inspection call at all
    has_mime_check = bool(_PHP_MIME_CHECK_RE.search(source))

    # Collect lines with whitelisted extension arrays to detect whitelist presence
    has_whitelist = bool(re.search(
        r"""(?:allowed|whitelist|permit)[^=]*=\s*(?:array|\[)""",
        source,
        re.IGNORECASE,
    ))

    for lineno, line in enumerate(lines, start=1):
        if _PHP_FILES_RE.search(line):
            issues = []
            if not has_mime_check:
                issues.append("no MIME-type inspection")
            if not has_whitelist:
                issues.append("no extension whitelist")
            if issues:
                findings.append(
                    Finding(
                        file=filename,
                        line=lineno,
                        vuln_type="Insecure File Upload (CWE-434/CWE-22)",
                        snippet=line.strip(),
                        remediation=(
                            "Validate the uploaded file's MIME type with finfo_open() / "
                            "mime_content_type(), enforce a strict extension whitelist, and "
                            "store files outside the web root with a generated name."
                        ),
                    )
                )

    return findings


# Directories that should never be scanned (virtual envs, caches, VCS, build
# artefacts, third-party package trees, and test directories).
IGNORE_DIRS: set[str] = {
    ".git",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    "tests",
    "test",
    "testing",
}


def _is_test_file(name: str) -> bool:
    """Return True if *name* looks like a test file (test_foo.py or foo_test.py)."""
    return name.startswith("test_") or name.endswith("_test.py")


def scan_directory(target: Path) -> List[Finding]:
    """Recursively scan all .py and .php files under *target*.

    Directories whose name appears in ``IGNORE_DIRS`` are skipped entirely so
    that virtual-environment libraries, caches, version-control internals, and
    test directories are never included in the results.  Individual files whose
    name matches the ``test_`` / ``_test.py`` convention are also skipped so
    that test helpers placed outside a dedicated test directory are excluded.
    """
    all_findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(target):
        # Prune ignored directories in-place so os.walk won't descend into them.
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for filename in sorted(filenames):
            if _is_test_file(filename):
                continue
            src_file = Path(dirpath) / filename
            if src_file.suffix.lower() in {".py", ".php"}:
                all_findings.extend(scan_file(src_file))
    return all_findings
