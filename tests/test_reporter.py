"""
tests/test_reporter.py — unit tests for core.reporter

Covers all four export formats:
  - table  (render_table — smoke-test only, Rich output is terminal-bound)
  - json   (render_json)
  - sarif  (render_sarif)
  - markdown (render_markdown)

Also covers the unified render_findings() entry-point, including file output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.detector import Finding
from core.reporter import (
    render_findings,
    render_json,
    render_markdown,
    render_sarif,
    render_table,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    file: str = "app/views.py",
    line: int = 42,
    vuln_type: str = "Unparameterised SQL",
    snippet: str = 'c.execute(f"SELECT * FROM users WHERE id = {uid}")',
    remediation: str = "Use parameterised queries.",
) -> Finding:
    return Finding(
        file=file,
        line=line,
        vuln_type=vuln_type,
        snippet=snippet,
        remediation=remediation,
    )


SQL_FINDING = _make_finding()
XSS_FINDING = _make_finding(
    file="app/views.py",
    line=10,
    vuln_type="Potential XSS Sink",
    snippet="return Markup(name)",
    remediation="Avoid rendering raw user input as HTML.",
)
SECRET_FINDING = _make_finding(
    file="config/settings.py",
    line=3,
    vuln_type="Hardcoded Secret (AWS Access Key ID)",
    snippet='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
    remediation="Load secrets from environment variables.",
)
ALL_FINDINGS = [SQL_FINDING, XSS_FINDING, SECRET_FINDING]


# ===========================================================================
# Table format — smoke tests (no terminal interaction)
# ===========================================================================

class TestRenderTable:

    def test_no_findings_does_not_raise(self):
        """render_table with an empty list must not raise."""
        render_table([], ".")

    def test_findings_does_not_raise(self):
        """render_table with findings must not raise."""
        render_table(ALL_FINDINGS, "myproject")


# ===========================================================================
# JSON format
# ===========================================================================

class TestRenderJson:

    def test_returns_valid_json(self):
        out = render_json(ALL_FINDINGS)
        data = json.loads(out)   # must not raise
        assert isinstance(data, dict)

    def test_total_matches_findings_count(self):
        out = render_json(ALL_FINDINGS)
        data = json.loads(out)
        assert data["total"] == len(ALL_FINDINGS)

    def test_findings_array_length(self):
        out = render_json(ALL_FINDINGS)
        data = json.loads(out)
        assert len(data["findings"]) == len(ALL_FINDINGS)

    def test_finding_fields_present(self):
        out = render_json([SQL_FINDING])
        data = json.loads(out)
        f = data["findings"][0]
        assert f["file"] == SQL_FINDING.file
        assert f["line"] == SQL_FINDING.line
        assert f["vuln_type"] == SQL_FINDING.vuln_type
        assert f["snippet"] == SQL_FINDING.snippet
        assert f["remediation"] == SQL_FINDING.remediation

    def test_generated_at_present(self):
        out = render_json(ALL_FINDINGS)
        data = json.loads(out)
        assert "generated_at" in data

    def test_empty_findings(self):
        out = render_json([])
        data = json.loads(out)
        assert data["total"] == 0
        assert data["findings"] == []


# ===========================================================================
# SARIF v2.1.0 format
# ===========================================================================

class TestRenderSarif:

    def _parse(self, findings=None, target_dir="."):
        if findings is None:
            findings = ALL_FINDINGS
        return json.loads(render_sarif(findings, target_dir))

    def test_returns_valid_json(self):
        json.loads(render_sarif(ALL_FINDINGS))  # must not raise

    def test_sarif_version(self):
        data = self._parse()
        assert data["version"] == "2.1.0"

    def test_sarif_schema_field(self):
        data = self._parse()
        assert "$schema" in data
        assert "sarif-schema-2.1.0" in data["$schema"]

    def test_single_run(self):
        data = self._parse()
        assert len(data["runs"]) == 1

    def test_tool_driver_name(self):
        data = self._parse()
        assert data["runs"][0]["tool"]["driver"]["name"] == "devsecops-scanner"

    def test_rules_present(self):
        data = self._parse()
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert {"DS001", "DS002", "DS003"}.issubset(rule_ids)

    def test_result_count_matches(self):
        data = self._parse()
        assert len(data["runs"][0]["results"]) == len(ALL_FINDINGS)

    def test_sql_maps_to_ds001(self):
        data = json.loads(render_sarif([SQL_FINDING]))
        result = data["runs"][0]["results"][0]
        assert result["ruleId"] == "DS001"

    def test_xss_maps_to_ds002(self):
        data = json.loads(render_sarif([XSS_FINDING]))
        result = data["runs"][0]["results"][0]
        assert result["ruleId"] == "DS002"

    def test_secret_maps_to_ds003(self):
        data = json.loads(render_sarif([SECRET_FINDING]))
        result = data["runs"][0]["results"][0]
        assert result["ruleId"] == "DS003"

    def test_sql_level_is_error(self):
        data = json.loads(render_sarif([SQL_FINDING]))
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_xss_level_is_warning(self):
        data = json.loads(render_sarif([XSS_FINDING]))
        assert data["runs"][0]["results"][0]["level"] == "warning"

    def test_secret_level_is_error(self):
        data = json.loads(render_sarif([SECRET_FINDING]))
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_location_start_line(self):
        data = json.loads(render_sarif([SQL_FINDING]))
        region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == SQL_FINDING.line

    def test_location_snippet(self):
        data = json.loads(render_sarif([SQL_FINDING]))
        region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["snippet"]["text"] == SQL_FINDING.snippet

    def test_empty_findings_produces_empty_results(self):
        data = json.loads(render_sarif([]))
        assert data["runs"][0]["results"] == []

    def test_original_uri_base_ids_present(self):
        data = self._parse()
        assert "originalUriBaseIds" in data["runs"][0]
        assert "%SRCROOT%" in data["runs"][0]["originalUriBaseIds"]


# ===========================================================================
# Markdown format
# ===========================================================================

class TestRenderMarkdown:

    def test_no_findings_clean_message(self):
        md = render_markdown([])
        assert "No vulnerabilities" in md
        assert "✅" in md

    def test_contains_header(self):
        md = render_markdown(ALL_FINDINGS)
        assert "## 🔍 Security Scan Results" in md

    def test_total_count_in_output(self):
        md = render_markdown(ALL_FINDINGS)
        assert str(len(ALL_FINDINGS)) in md

    def test_collapsible_details_per_file(self):
        md = render_markdown(ALL_FINDINGS)
        # Two distinct files → two <details> blocks
        assert md.count("<details>") == 2

    def test_summary_includes_finding_filename(self):
        md = render_markdown([SQL_FINDING])
        assert SQL_FINDING.file in md

    def test_line_number_present(self):
        md = render_markdown([SQL_FINDING])
        assert str(SQL_FINDING.line) in md

    def test_snippet_in_code_fence(self):
        md = render_markdown([SQL_FINDING])
        assert "```python" in md
        assert SQL_FINDING.snippet in md

    def test_remediation_present(self):
        md = render_markdown([SQL_FINDING])
        assert SQL_FINDING.remediation in md

    def test_severity_table_present(self):
        md = render_markdown(ALL_FINDINGS)
        # Markdown table pipe characters
        assert "| Severity |" in md

    def test_generated_footer_present(self):
        md = render_markdown(ALL_FINDINGS)
        assert "devsecops-scanner" in md

    def test_sql_emoji_present(self):
        md = render_markdown([SQL_FINDING])
        assert "🔴" in md

    def test_xss_emoji_present(self):
        md = render_markdown([XSS_FINDING])
        assert "🟡" in md

    def test_secret_emoji_present(self):
        md = render_markdown([SECRET_FINDING])
        assert "🟣" in md


# ===========================================================================
# render_findings() unified entry-point
# ===========================================================================

class TestRenderFindings:

    def test_json_to_stdout(self, capsys):
        render_findings([SQL_FINDING], ".", fmt="json")
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 1

    def test_sarif_to_stdout(self, capsys):
        render_findings([SQL_FINDING], ".", fmt="sarif")
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["version"] == "2.1.0"

    def test_markdown_to_stdout(self, capsys):
        render_findings([SQL_FINDING], ".", fmt="markdown")
        captured = capsys.readouterr()
        assert "Security Scan Results" in captured.out

    def test_json_to_file(self, tmp_path):
        out_file = str(tmp_path / "report.json")
        render_findings([SQL_FINDING], ".", fmt="json", output=out_file)
        data = json.loads(Path(out_file).read_text())
        assert data["total"] == 1

    def test_sarif_to_file(self, tmp_path):
        out_file = str(tmp_path / "results.sarif")
        render_findings([SQL_FINDING], ".", fmt="sarif", output=out_file)
        data = json.loads(Path(out_file).read_text())
        assert data["version"] == "2.1.0"

    def test_markdown_to_file(self, tmp_path):
        out_file = str(tmp_path / "report.md")
        render_findings([SQL_FINDING], ".", fmt="markdown", output=out_file)
        content = Path(out_file).read_text()
        assert "Security Scan Results" in content

    def test_table_does_not_raise_no_findings(self):
        render_findings([], ".", fmt="table")

    def test_table_does_not_raise_with_findings(self):
        render_findings(ALL_FINDINGS, ".", fmt="table")

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="Unknown format"):
            render_findings([], ".", fmt="xml")  # type: ignore[arg-type]
