"""
ui/dashboard.py — DevSecOps Scanner interactive Streamlit triage dashboard.

Run with:
    streamlit run ui/dashboard.py

Features
--------
* Target folder selector + "Run Scan" button
* Metrics bar: total findings, critical (RCE/SQL), high (secrets), medium (XSS),
  auto-remediation readiness %
* Interactive finding cards with:
  - Syntax-highlighted code snippet
  - Adversary PoC payload & attack scenario in a red warning alert
  - Side-by-side diff viewer (original vs patched)
  - "Apply Remediation" button that writes the fix to disk in real time
"""

from __future__ import annotations

import difflib
import sys
from pathlib import Path

# Ensure the project root is on the path when run from any directory
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

from core.detector import scan_directory, Finding
from core.patcher import compute_patch, apply_patch, PatchResult
from core.adversary import analyse, AdversaryAnalysis

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="DevSecOps Scanner",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Custom CSS — minimal, matches project palette
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .ds-header {
        background: #0f172a;
        border: 1px solid #1e293b;
        color: #f8fafc;
        padding: 1.2rem 1.6rem;
        border-radius: 8px;
        margin-bottom: 1.2rem;
    }
    .ds-header h1 { margin: 0; font-size: 1.6rem; color: #f8fafc; }
    .ds-header p  { margin: 0.2rem 0 0; font-size: 0.9rem; color: #94a3b8; }
    .metric-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.25);
    }
    .metric-card .val { font-size: 2rem; font-weight: 700; color: #f8fafc; }
    .metric-card .lbl { font-size: 0.8rem; color: #94a3b8; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
    .poc-alert {
        background: #2b1115;
        border-left: 4px solid #ef4444;
        border-radius: 6px;
        padding: 0.9rem 1.2rem;
        margin: 0.8rem 0;
        color: #f3f4f6;
    }
    .poc-alert strong { color: #fca5a5; font-size: 0.95rem; }
    .poc-alert b { color: #e5e7eb; }
    .poc-alert code {
        background: #111827;
        color: #38bdf8;
        padding: 3px 7px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.88rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown(
    """
    <div class="ds-header">
        <h1>🔐 DevSecOps Scanner</h1>
        <p>Static analysis · Adversary simulation · Auto-remediation</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar — target selector
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("⚙️ Scan Settings")
    target_input = st.text_input(
        "Target folder",
        value=str(_ROOT / "mock_vulnerable_repo"),
        help="Absolute or relative path to the directory you want to scan.",
    )
    run_button = st.button("🚀 Run Scan", use_container_width=True, type="primary")

# Also show a compact control row in the main area for quick access
col_path, col_btn = st.columns([4, 1])
with col_path:
    target_main = st.text_input(
        "Target folder",
        value=target_input,
        key="target_main",
        label_visibility="collapsed",
        placeholder="Enter path to scan…",
    )
with col_btn:
    run_main = st.button("▶ Run Scan", use_container_width=True, type="primary", key="run_main")

run = run_button or run_main
target_path_str = target_main or target_input

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

if "findings" not in st.session_state:
    st.session_state["findings"] = []
if "patches" not in st.session_state:
    st.session_state["patches"] = {}   # finding index → PatchResult | None
if "adversary" not in st.session_state:
    st.session_state["adversary"] = {}  # finding index → AdversaryAnalysis
if "applied" not in st.session_state:
    st.session_state["applied"] = set()  # set of finding indices already patched

# ---------------------------------------------------------------------------
# Run scan
# ---------------------------------------------------------------------------

if run:
    target = Path(target_path_str)
    if not target.is_dir():
        st.error(f"**{target_path_str}** is not a valid directory.")
    else:
        with st.spinner("Scanning…"):
            findings = scan_directory(target)
            patches: dict[int, PatchResult | None] = {}
            adversary: dict[int, AdversaryAnalysis] = {}
            for i, f in enumerate(findings):
                patches[i] = compute_patch(f, project_root=target.resolve())
                adversary[i] = analyse(f)

        st.session_state["findings"] = findings
        st.session_state["patches"] = patches
        st.session_state["adversary"] = adversary
        st.session_state["applied"] = set()
        st.success(f"Scan complete — **{len(findings)}** finding(s) in `{target_path_str}`")

findings: list[Finding] = st.session_state["findings"]
patches_map: dict[int, PatchResult | None] = st.session_state["patches"]
adversary_map: dict[int, AdversaryAnalysis] = st.session_state["adversary"]
applied: set[int] = st.session_state["applied"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity(f: Finding) -> str:
    vt = f.vuln_type.lower()
    if "command injection" in vt or "sql" in vt or "file upload" in vt:
        return "critical"
    if "secret" in vt or "hardcoded" in vt:
        return "high"
    if "xss" in vt:
        return "medium"
    return "low"


def _severity_emoji(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")


def _cvss_color(score: float) -> str:
    if score >= 9.0:
        return "#dc2626"
    if score >= 7.0:
        return "#f97316"
    if score >= 4.0:
        return "#eab308"
    return "#3b82f6"


def _make_diff(patch: PatchResult) -> str:
    before = patch.original_lines
    after = patch.patched_lines
    diff = list(difflib.unified_diff(
        before, after,
        fromfile="original",
        tofile="patched",
        lineterm="",
    ))
    return "\n".join(diff) if diff else "(no textual change)"


def _remediation_ready(total: int, patchable: int) -> int:
    if total == 0:
        return 0
    return round(patchable / total * 100)


# ---------------------------------------------------------------------------
# Metrics bar
# ---------------------------------------------------------------------------

if findings:
    n_total = len(findings)
    n_critical = sum(1 for f in findings if _severity(f) == "critical")
    n_high = sum(1 for f in findings if _severity(f) == "high")
    n_medium = sum(1 for f in findings if _severity(f) == "medium")
    n_patchable = sum(1 for v in patches_map.values() if v is not None)
    readiness = _remediation_ready(n_total, n_patchable)

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(
            f'<div class="metric-card"><div class="val">{n_total}</div>'
            f'<div class="lbl">Total Findings</div></div>',
            unsafe_allow_html=True,
        )
    with m2:
        st.markdown(
            f'<div class="metric-card"><div class="val" style="color:#dc2626">{n_critical}</div>'
            f'<div class="lbl">Critical (RCE/SQLi)</div></div>',
            unsafe_allow_html=True,
        )
    with m3:
        st.markdown(
            f'<div class="metric-card"><div class="val" style="color:#f97316">{n_high}</div>'
            f'<div class="lbl">High (Secrets)</div></div>',
            unsafe_allow_html=True,
        )
    with m4:
        st.markdown(
            f'<div class="metric-card"><div class="val" style="color:#eab308">{n_medium}</div>'
            f'<div class="lbl">Medium (XSS)</div></div>',
            unsafe_allow_html=True,
        )
    with m5:
        st.markdown(
            f'<div class="metric-card"><div class="val" style="color:#3b82d4">{readiness}%</div>'
            f'<div class="lbl">Auto-Remediation Ready</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # -----------------------------------------------------------------------
    # Finding cards
    # -----------------------------------------------------------------------

    st.subheader(f"🔎 Findings ({n_total})")

    # Group by file for cleaner display
    files_seen: dict[str, list[int]] = {}
    for i, f in enumerate(findings):
        files_seen.setdefault(f.file, []).append(i)

    for file_path, indices in files_seen.items():
        with st.expander(f"📄 `{file_path}` — {len(indices)} finding(s)", expanded=True):
            for i in indices:
                f = findings[i]
                patch = patches_map.get(i)
                adv = adversary_map.get(i)
                sev = _severity(f)
                already_applied = i in applied

                # Card header
                st.markdown(
                    f'<div class="finding-card sev-{sev}">',
                    unsafe_allow_html=True,
                )

                head_col, badge_col = st.columns([5, 1])
                with head_col:
                    st.markdown(
                        f"#### {_severity_emoji(sev)} {f.vuln_type} &nbsp;&nbsp;"
                        f"<span style='color:#94a3b8; font-size:0.9rem; font-weight:normal;'>Line {f.line}</span>",
                        unsafe_allow_html=True,
                    )
                with badge_col:
                    if adv:
                        color = _cvss_color(adv.cvss_score)
                        st.markdown(
                            f"<div style='text-align:right;'><span style='background:{color}; color:#ffffff; padding:3px 10px;"
                            f"border-radius:4px; font-size:0.8rem; font-weight:700; display:inline-block;'>"
                            f"CVSS {adv.cvss_score}</span></div>",
                            unsafe_allow_html=True,
                        )

                # Code snippet
                st.code(f.snippet or "(no snippet)", language="python")

                # Adversary block
                if adv:
                    st.markdown(
                        f'<div class="poc-alert">'
                        f'<strong>⚠️ Adversary Simulation — {adv.cwe_id}</strong><br>'
                        f'<span style="color:#d1d5db; display:block; margin: 4px 0;"><b>Attack Scenario:</b> {adv.attack_scenario}</span>'
                        f'<span style="color:#d1d5db;"><b>PoC Payload:</b> <code>{adv.poc_payload}</code></span>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

                # Diff viewer + apply button
                if patch is not None and not already_applied:
                    st.markdown("**📋 Proposed Patch**")
                    diff_left, diff_right = st.columns(2)
                    with diff_left:
                        st.markdown("*Original*")
                        st.code("".join(patch.original_lines), language="python")
                    with diff_right:
                        st.markdown("*Patched*")
                        st.code("".join(patch.patched_lines), language="python")

                    if st.button(
                        f"✅ Apply Remediation",
                        key=f"apply_{i}",
                        type="primary",
                    ):
                        try:
                            apply_patch(patch)
                            st.session_state["applied"].add(i)
                            st.success(f"Patch applied to `{f.file}` line {f.line}")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Failed to apply patch: {exc}")

                elif already_applied:
                    st.success("✔ Remediation already applied in this session.")
                else:
                    st.info("ℹ No automated patch available for this finding type.")

                st.markdown("<hr style='border:0; height:1px; background:#1e293b; margin:1rem 0;'>", unsafe_allow_html=True)

elif not run:
    st.info("👆 Enter a target folder above and click **Run Scan** to start.")
else:
    st.success("✅ No vulnerabilities detected in the scanned directory.")
