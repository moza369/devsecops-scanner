"""
reporter.py — multi-format scan reporter.

Supported formats:
  table    — Rich colour-coded terminal table (default)
  json     — Machine-readable dump of all findings
  sarif    — SARIF v2.1.0 for GitHub Security tab upload
  markdown — GitHub PR comment with collapsible finding blocks
"""

from __future__ import annotations

import json
import textwrap
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Literal, Optional

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text
from rich.panel import Panel

from core.detector import Finding

console = Console()

Format = Literal["table", "json", "sarif", "markdown"]

# Severity colour map keyed on substring of vuln_type
_COLOUR_MAP: dict[str, str] = {
    "SQL": "bold red",
    "XSS": "bold yellow",
    "Secret": "bold magenta",
}

# SARIF severity mapping
_SARIF_SEVERITY: dict[str, str] = {
    "SQL": "error",
    "XSS": "warning",
    "Secret": "error",
}

# SARIF rule definitions
_SARIF_RULES = [
    {
        "id": "DS001",
        "name": "UnparameterisedSQL",
        "shortDescription": {"text": "Unparameterised SQL query"},
        "fullDescription": {
            "text": (
                "A SQL query is constructed using string formatting or concatenation, "
                "which may allow SQL injection attacks."
            )
        },
        "helpUri": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "properties": {"tags": ["security", "correctness"], "precision": "high"},
    },
    {
        "id": "DS002",
        "name": "PotentialXSSSink",
        "shortDescription": {"text": "Potential XSS sink"},
        "fullDescription": {
            "text": (
                "Raw user-controlled data is passed to an HTML rendering function, "
                "which may allow cross-site scripting attacks."
            )
        },
        "helpUri": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "properties": {"tags": ["security"], "precision": "medium"},
    },
    {
        "id": "DS003",
        "name": "HardcodedSecret",
        "shortDescription": {"text": "Hardcoded secret or credential"},
        "fullDescription": {
            "text": (
                "A secret, token, API key or password is hardcoded in the source file. "
                "Rotate the credential and load it from environment variables or a secrets manager."
            )
        },
        "helpUri": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        "properties": {"tags": ["security", "maintainability"], "precision": "high"},
    },
]


def _vuln_colour(vuln_type: str) -> str:
    for key, colour in _COLOUR_MAP.items():
        if key.upper() in vuln_type.upper():
            return colour
    return "bold white"


def _sarif_rule_id(vuln_type: str) -> str:
    upper = vuln_type.upper()
    if "SQL" in upper:
        return "DS001"
    if "XSS" in upper:
        return "DS002"
    return "DS003"


def _sarif_severity(vuln_type: str) -> str:
    upper = vuln_type.upper()
    for key, level in _SARIF_SEVERITY.items():
        if key.upper() in upper:
            return level
    return "warning"


# ---------------------------------------------------------------------------
# Table format (Rich terminal output)
# ---------------------------------------------------------------------------

def render_table(findings: List[Finding], target_dir: str) -> None:
    """Print a Rich table of *findings* to the terminal."""
    if not findings:
        console.print(
            Panel(
                "[bold green]✔ No vulnerabilities detected.[/bold green]",
                title="Scan Complete",
                border_style="green",
            )
        )
        return

    table = Table(
        title=f"[bold]DevSecOps Scan Results — {target_dir}[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
        expand=True,
    )

    table.add_column("File", style="cyan", no_wrap=False, ratio=3)
    table.add_column("Line", style="bold white", justify="right", ratio=1)
    table.add_column("Vulnerability", ratio=3)
    table.add_column("Snippet", style="dim", ratio=4)
    table.add_column("Remediation", ratio=5)

    for f in findings:
        colour = _vuln_colour(f.vuln_type)
        table.add_row(
            f.file,
            str(f.line),
            Text(f.vuln_type, style=colour),
            f.snippet,
            f.remediation,
        )

    console.print(table)

    counts: Counter[str] = Counter(f.vuln_type for f in findings)
    summary_lines = [f"[bold]Total findings: {len(findings)}[/bold]"]
    for vuln_type, count in counts.most_common():
        colour = _vuln_colour(vuln_type)
        summary_lines.append(f"  [{colour}]{vuln_type}[/{colour}]: {count}")

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="Summary",
            border_style="red" if findings else "green",
        )
    )


# ---------------------------------------------------------------------------
# JSON format
# ---------------------------------------------------------------------------

def render_json(findings: List[Finding]) -> str:
    """Return a machine-readable JSON dump of all findings."""
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(findings),
        "findings": [f.model_dump() for f in findings],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# SARIF v2.1.0 format
# ---------------------------------------------------------------------------

def render_sarif(findings: List[Finding], target_dir: str = ".") -> str:
    """Return a valid SARIF v2.1.0 document as a JSON string."""
    results: list[dict] = []

    for finding in findings:
        rule_id = _sarif_rule_id(finding.vuln_type)
        level = _sarif_severity(finding.vuln_type)

        # Normalise file path to a URI
        try:
            uri = Path(finding.file).as_uri()
        except ValueError:
            uri = finding.file

        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"{finding.vuln_type}: {finding.remediation}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line,
                            "snippet": {"text": finding.snippet},
                        },
                    }
                }
            ],
        }
        results.append(result)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "devsecops-scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-org/devsecops-scanner",
                        "rules": _SARIF_RULES,
                    }
                },
                "results": results,
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": Path(target_dir).resolve().as_uri() + "/"}
                },
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


# ---------------------------------------------------------------------------
# Markdown format (GitHub PR comment)
# ---------------------------------------------------------------------------

def render_markdown(findings: List[Finding], target_dir: str = ".") -> str:
    """Return a Markdown GitHub PR comment summary with collapsible blocks."""
    if not findings:
        return (
            "## ✅ Security Scan — No Findings\n\n"
            "No vulnerabilities were detected in this pull request.\n"
        )

    counts: Counter[str] = Counter(f.vuln_type for f in findings)
    severity_emoji = {"SQL": "🔴", "XSS": "🟡", "Secret": "🟣"}

    lines: list[str] = [
        "## 🔍 Security Scan Results\n",
        f"**{len(findings)} finding(s)** detected in `{target_dir}`\n",
        "| Severity | Type | Count |",
        "|----------|------|-------|",
    ]
    for vuln_type, count in counts.most_common():
        emoji = next(
            (v for k, v in severity_emoji.items() if k.upper() in vuln_type.upper()),
            "⚪",
        )
        lines.append(f"| {emoji} | {vuln_type} | {count} |")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Group findings by file
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    for filepath, file_findings in sorted(by_file.items()):
        lines.append(
            f"<details>\n<summary><b>{filepath}</b> "
            f"— {len(file_findings)} finding(s)</summary>\n"
        )
        for f in file_findings:
            emoji = next(
                (v for k, v in severity_emoji.items() if k.upper() in f.vuln_type.upper()),
                "⚪",
            )
            lines.append(f"\n#### {emoji} {f.vuln_type} — Line {f.line}\n")
            lines.append("```python")
            lines.append(f.snippet if f.snippet else "(no snippet)")
            lines.append("```\n")
            lines.append(f"> **Remediation:** {f.remediation}\n")

        lines.append("</details>\n")

    lines.append("---")
    lines.append(
        "_Generated by [devsecops-scanner](https://github.com/your-org/devsecops-scanner) "
        f"on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_"
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def render_findings(
    findings: List[Finding],
    target_dir: str,
    fmt: Format = "table",
    output: Optional[str] = None,
) -> None:
    """Render *findings* in the requested *fmt*.

    If *output* is given the rendered content is written to that file path.
    For ``table`` format the content is always printed to the terminal
    regardless of *output*.
    """
    if fmt == "table":
        render_table(findings, target_dir)
        return

    if fmt == "json":
        content = render_json(findings)
    elif fmt == "sarif":
        content = render_sarif(findings, target_dir)
    elif fmt == "markdown":
        content = render_markdown(findings, target_dir)
    else:
        raise ValueError(f"Unknown format: {fmt!r}")

    if output:
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"[bold green]✔[/bold green] Report written to [cyan]{output}[/cyan]")
    else:
        print(content)
