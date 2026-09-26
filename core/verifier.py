"""
verifier.py — Post-patch remediation verifier.

Checks that an automated patch both:
  1. Preserves Python syntax (via ``ast.parse``).
  2. Actually eliminated the target vulnerability (by re-running ``scan_file``
     and confirming the specific finding is no longer present).
"""

from __future__ import annotations

import ast
from pathlib import Path

from core.detector import scan_file, Finding


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_remediation(file_path: Path) -> dict:
    """Verify that *file_path* is syntactically valid and free of the
    vulnerabilities that were previously reported at the given location.

    Returns a dict with the following keys:

    ``syntax_ok`` (bool)
        ``True`` if ``ast.parse`` succeeds; ``False`` otherwise.

    ``syntax_error`` (str | None)
        Human-readable description of the ``SyntaxError`` if parsing failed,
        else ``None``.

    ``findings`` (list[Finding])
        All vulnerability findings still present in the file after patching.
        An empty list means the file is clean.

    ``clean`` (bool)
        ``True`` iff *both* ``syntax_ok`` is ``True`` and ``findings`` is
        empty — i.e. the remediation was fully successful.
    """
    result: dict = {
        "syntax_ok": False,
        "syntax_error": None,
        "findings": [],
        "clean": False,
    }

    # ------------------------------------------------------------------
    # 1. Syntax check
    # ------------------------------------------------------------------
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result["syntax_error"] = f"Cannot read file: {exc}"
        return result

    try:
        ast.parse(source, filename=str(file_path))
        result["syntax_ok"] = True
    except SyntaxError as exc:
        result["syntax_error"] = (
            f"SyntaxError at line {exc.lineno}: {exc.msg}"
        )
        return result  # no point scanning a broken file

    # ------------------------------------------------------------------
    # 2. Re-scan for remaining vulnerabilities
    # ------------------------------------------------------------------
    remaining = scan_file(file_path)
    result["findings"] = remaining
    result["clean"] = len(remaining) == 0

    return result
