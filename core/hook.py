"""
hook.py — Git pre-commit hook installer.

Installs a pre-commit hook that runs the DevSecOps scanner against the
staged project root.  If critical vulnerabilities or hardcoded secrets are
found the hook aborts the commit (exit code 1) and prints remediation
guidance; a clean scan allows the commit through (exit code 0).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

# ---------------------------------------------------------------------------
# Hook script template
# ---------------------------------------------------------------------------

HOOK_SCRIPT = """#!/usr/bin/env bash
# DevSecOps Scanner Pre-Commit Gate
echo "🔒 [DevSecOps Scanner] Auditing staged code before commit..."

python3 main.py . --format table
SCAN_EXIT_CODE=$?

if [ $SCAN_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ Commit rejected: Critical security findings detected in source code."
    echo "👉 Run 'python3 main.py . --fix' or launch 'streamlit run ui/dashboard.py' to remediate."
    exit 1
fi

echo "✅ [DevSecOps Scanner] Security checks passed."
exit 0
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def install_pre_commit_hook(repo_root: Path) -> tuple[bool, str]:
    """Write the pre-commit hook script into *repo_root*/.git/hooks/pre-commit.

    Returns ``(True, message)`` on success or ``(False, error_message)`` on
    failure.
    """
    git_dir = repo_root / ".git"
    if not git_dir.is_dir():
        return False, f"No .git directory found under '{repo_root.resolve()}'. Is this a Git repository?"

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    hook_path = hooks_dir / "pre-commit"

    try:
        hook_path.write_text(HOOK_SCRIPT, encoding="utf-8")
        # Set rwxr-xr-x (0o755)
        current_mode = hook_path.stat().st_mode
        hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError as exc:
        return False, f"Failed to write hook: {exc}"

    return True, f"Pre-commit hook installed at '{hook_path}'."
