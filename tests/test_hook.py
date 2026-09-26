"""
tests/test_hook.py — unit tests for core.hook

Tests cover:
  - Successful hook installation into a real .git/hooks/ directory.
  - Hook file is executable.
  - Hook script content includes the scanner invocation.
  - Failure when the target is not a Git repository.
  - Idempotent re-installation (overwrite existing hook).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from core.hook import install_pre_commit_hook


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_git_repo(base: Path) -> Path:
    """Create a minimal fake git repo (only the .git/hooks directory)."""
    (base / ".git" / "hooks").mkdir(parents=True)
    return base


# ===========================================================================
# Successful installation
# ===========================================================================

class TestInstallPreCommitHook:

    def test_returns_true_on_success(self, tmp_path):
        repo = _make_git_repo(tmp_path)
        ok, msg = install_pre_commit_hook(repo)
        assert ok is True
        assert "pre-commit" in msg.lower()

    def test_hook_file_exists(self, tmp_path):
        repo = _make_git_repo(tmp_path)
        install_pre_commit_hook(repo)
        hook_path = repo / ".git" / "hooks" / "pre-commit"
        assert hook_path.exists()

    def test_hook_file_is_executable(self, tmp_path):
        repo = _make_git_repo(tmp_path)
        install_pre_commit_hook(repo)
        hook_path = repo / ".git" / "hooks" / "pre-commit"
        mode = hook_path.stat().st_mode
        # Owner, group, and other execute bits must all be set
        assert mode & stat.S_IXUSR, "owner execute bit not set"
        assert mode & stat.S_IXGRP, "group execute bit not set"
        assert mode & stat.S_IXOTH, "other execute bit not set"

    def test_hook_contains_scanner_invocation(self, tmp_path):
        repo = _make_git_repo(tmp_path)
        install_pre_commit_hook(repo)
        content = (repo / ".git" / "hooks" / "pre-commit").read_text()
        assert "main.py" in content
        assert "--format table" in content

    def test_hook_contains_shebang(self, tmp_path):
        repo = _make_git_repo(tmp_path)
        install_pre_commit_hook(repo)
        content = (repo / ".git" / "hooks" / "pre-commit").read_text()
        assert content.startswith("#!/usr/bin/env bash")

    def test_hook_exits_1_on_findings(self, tmp_path):
        """The script must contain an exit 1 path guarded by scan exit code."""
        repo = _make_git_repo(tmp_path)
        install_pre_commit_hook(repo)
        content = (repo / ".git" / "hooks" / "pre-commit").read_text()
        assert "exit 1" in content
        assert "SCAN_EXIT" in content

    def test_hook_guidance_mentions_fix_and_dashboard(self, tmp_path):
        """Blocked-commit message must reference --fix and the dashboard."""
        repo = _make_git_repo(tmp_path)
        install_pre_commit_hook(repo)
        content = (repo / ".git" / "hooks" / "pre-commit").read_text()
        assert "--fix" in content
        assert "dashboard" in content.lower()

    def test_idempotent_reinstall(self, tmp_path):
        """Calling install twice overwrites the hook without error."""
        repo = _make_git_repo(tmp_path)
        install_pre_commit_hook(repo)
        ok, msg = install_pre_commit_hook(repo)
        assert ok is True
        hook_path = repo / ".git" / "hooks" / "pre-commit"
        # File still executable after overwrite
        assert hook_path.stat().st_mode & stat.S_IXUSR


# ===========================================================================
# Error handling
# ===========================================================================

class TestInstallPreCommitHookErrors:

    def test_fails_when_not_a_git_repo(self, tmp_path):
        # tmp_path has no .git directory
        ok, msg = install_pre_commit_hook(tmp_path)
        assert ok is False
        assert ".git" in msg or "Git" in msg

    def test_error_message_is_informative(self, tmp_path):
        ok, msg = install_pre_commit_hook(tmp_path)
        assert len(msg) > 10  # non-trivial message

    def test_hooks_dir_created_if_missing(self, tmp_path):
        """If .git exists but hooks/ sub-dir is absent, it should be created."""
        (tmp_path / ".git").mkdir()
        # No hooks/ sub-dir
        ok, msg = install_pre_commit_hook(tmp_path)
        assert ok is True
        assert (tmp_path / ".git" / "hooks" / "pre-commit").exists()
