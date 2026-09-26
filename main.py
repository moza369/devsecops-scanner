#!/usr/bin/env python3
"""
main.py — DevSecOps scanner CLI entrypoint.

Usage:
    python main.py <target_directory>                           # scan, table output
    python main.py <target_directory> --fix                     # scan + interactive auto-remediation
    python main.py <target_directory> --format sarif --output results.sarif
    python main.py <target_directory> --format markdown
    python main.py <target_directory> --format json
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

from core.hook import install_pre_commit_hook

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.prompt import Confirm

from core.detector import scan_directory
from core.reporter import render_findings
from core.patcher import patch_findings, apply_patch, PatchResult

console = Console()


# ---------------------------------------------------------------------------
# Diff rendering
# ---------------------------------------------------------------------------

def _render_diff(result: PatchResult) -> None:
    """Print a colour-coded unified diff for one PatchResult."""
    file_path = result.finding.file
    start = result.start_line

    # Build labelled before/after line lists
    before_lines = [
        f"{start + i:>4} | {l}" for i, l in enumerate(result.original_lines)
    ]
    after_lines = [
        f"{start + i:>4} | {l}" for i, l in enumerate(result.patched_lines)
    ]

    diff = list(
        difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        )
    )

    if not diff:
        return

    diff_text = "\n".join(diff)
    console.print(
        Syntax(diff_text, "diff", theme="monokai", line_numbers=False),
    )

    # Surface any side-effects
    ef = result.extra_files
    notes: list[str] = []
    if "__import_os__" in ef:
        notes.append("[yellow]  + will inject[/yellow] [bold]import os[/bold]")
    if "__env_example__" in ef:
        env_key = ef.get("__env_key__", "").strip()
        notes.append(
            f"[yellow]  + will append[/yellow] [bold]{env_key}[/bold]"
            f" to [cyan]{ef['__env_example__']}[/cyan]"
        )
    for note in notes:
        console.print(note)


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devsecops-scanner",
        description="Static analysis tool: SQL injection, XSS sinks, hardcoded secrets.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        metavar="TARGET_DIR",
        help="Path to the directory to scan.",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        default=False,
        help="Install a Git pre-commit hook that blocks commits with critical findings.",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        default=False,
        help="Interactively apply auto-remediation patches for detected findings.",
    )
    parser.add_argument(
        "--format",
        dest="fmt",
        choices=["table", "json", "sarif", "markdown"],
        default="table",
        metavar="FORMAT",
        help="Output format: table (default), json, sarif, markdown.",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Write report to FILE instead of stdout (ignored for --format table).",
    )
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # --install-hook: write .git/hooks/pre-commit and exit
    # ------------------------------------------------------------------
    if args.install_hook:
        ok, msg = install_pre_commit_hook(Path("."))
        if ok:
            console.print(f"[bold green]✔[/bold green] {msg}")
            sys.exit(0)
        else:
            console.print(f"[bold red]✖[/bold red] {msg}")
            sys.exit(1)

    if not args.target:
        parser.error("TARGET_DIR is required unless --install-hook is used.")

    target = Path(args.target)
    if not target.is_dir():
        console.print(f"[bold red]Error:[/bold red] '{target}' is not a directory.")
        sys.exit(1)

    # Only print the banner for interactive (table) mode
    if args.fmt == "table":
        console.print(f"\n[bold cyan]Scanning:[/bold cyan] {target.resolve()}\n")

    findings = scan_directory(target)
    render_findings(findings, str(target), fmt=args.fmt, output=args.output)

    if not findings:
        sys.exit(0)

    if not args.fix:
        # CI-friendly exit code; no patching.
        sys.exit(1)

    # ------------------------------------------------------------------
    # --fix mode: compute patches, show diff, confirm, apply
    # ------------------------------------------------------------------
    patches = patch_findings(findings, project_root=target.resolve())

    patchable = len(patches)
    skipped = len(findings) - patchable
    console.print(
        f"\n[bold]Auto-remediation:[/bold] "
        f"[green]{patchable} patchable[/green]"
        + (f", [dim]{skipped} skipped (XSS / unknown)[/dim]" if skipped else "")
        + "\n"
    )

    applied = 0
    for i, patch in enumerate(patches, start=1):
        vtype = patch.finding.vuln_type
        ffile = patch.finding.file
        fline = patch.finding.line

        console.rule(
            f"[bold]Fix {i}/{patchable}[/bold]  "
            f"[yellow]{vtype}[/yellow]  "
            f"[cyan]{ffile}[/cyan]:[white]{fline}[/white]"
        )

        _render_diff(patch)
        console.print()

        confirmed = Confirm.ask(
            "  Apply this fix?",
            default=False,
            console=console,
        )
        console.print()

        if confirmed:
            try:
                apply_patch(patch)
                console.print(f"  [bold green]✔ Applied[/bold green]  {ffile}:{fline}\n")
                applied += 1
            except Exception as exc:  # noqa: BLE001
                console.print(f"  [bold red]✖ Failed:[/bold red] {exc}\n")
        else:
            console.print(f"  [dim]Skipped.[/dim]\n")

    console.print(
        Panel(
            f"[bold green]{applied}[/bold green] fix(es) applied  "
            f"| [dim]{patchable - applied} skipped[/dim]",
            title="Done",
            border_style="green" if applied else "dim",
        )
    )

    sys.exit(0 if applied == patchable else 1)


if __name__ == "__main__":
    main()
