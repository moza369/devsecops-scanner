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

_HOOK_SCRIPT = """\
#!/usr/bin/env bash
# DevSecOps scanner pre-commit hook (auto-generated — do not edit manually).
# Re-install with: python main.py --install-hook

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCANNER="$(dirname "$(realpath "$0")")/../../main.py"

# Locate main.py: try relative to .git/hooks, then fall back to CWD.
if [ ! -f "$SCANNER" ]; then
    SCANNER="$REPO_ROOT/main.py"
fi

echo "[devsecops-scanner] Running pre-commit security scan..."

# Run the scanner; capture its exit code without aborting the hook script.
set +e
python3 "$SCANNER" . --format table
SCAN_EXIT=$?
set -e

if [ "$SCAN_EXIT" -ne 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  🚨  COMMIT BLOCKED — security findings detected             ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Fix automatically:  python main.py . --fix                  ║"
    echo "║  Review in UI:       python -m streamlit run ui/dashboard.py ║"
    echo "║  Bypass (danger!):   git commit --no-verify                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    exit 1
fi

echo "[devsecops-scanner] No critical findings — commit allowed."
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
        hook_path.write_text(_HOOK_SCRIPT, encoding="utf-8")
        # Set rwxr-xr-x (0o755)
        current_mode = hook_path.stat().st_mode
        hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError as exc:
        return False, f"Failed to write hook: {exc}"

    return True, f"Pre-commit hook installed at '{hook_path}'."
