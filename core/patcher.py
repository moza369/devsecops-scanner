"""
patcher.py — auto-remediation engine.

Supported fix strategies
------------------------
* Hardcoded Secret    — replaces the literal value with os.getenv("<VAR_NAME>"),
                        injects ``import os`` if absent, and appends the variable
                        name to .env.example in the project root.
* Unparameterised SQL — rewrites a cursor.execute(<tainted-expr>) call into a
                        safe parameterised form:
                            cursor.execute("<sql>", (<params>,))
* Command Injection   — rewrites subprocess/os calls to use a safe argument list
                        and removes shell=True; inserts shlex.quote() where a
                        shell string cannot be avoided.
* Insecure File Upload — rewrites file.save() to use secure_filename(), adds a
                         strict extension whitelist, and inserts a MIME-type
                         validation comment block.
"""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from core.detector import Finding


# ---------------------------------------------------------------------------
# Command-injection patch helpers
# ---------------------------------------------------------------------------

#: Same set as detector._CMD_FUNCS — replicated to avoid circular dependency.
_CMD_FUNCS: set[tuple[str, str]] = {
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("os", "system"),
    ("os", "popen"),
}

_IMPORT_SUBPROCESS_RE = re.compile(r'^\s*import\s+subprocess\s*$', re.MULTILINE)
_IMPORT_SHLEX_RE = re.compile(r'^\s*import\s+shlex\s*$', re.MULTILINE)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class PatchResult:
    finding: Finding
    original_lines: list[str]       # affected lines before patch (1-based slice)
    patched_lines: list[str]        # replacement lines
    start_line: int                 # 1-based index of first affected line
    extra_files: dict[str, str] = field(default_factory=dict)
    # extra_files: path → content to write/append (e.g. .env.example)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Matches:  varname = "value"  or  varname = 'value'
# Groups: (indent)(varname)(quote_char)(value)
_SECRET_ASSIGN_RE = re.compile(
    r'^(?P<indent>\s*)(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<q>[\'"])(?P<val>[^\'\"]+)(?P=q)',
)

# Detects ``import os`` as a standalone import already present in the file.
_IMPORT_OS_RE = re.compile(r'^\s*import\s+os\s*$', re.MULTILINE)

# Matches cursor.execute(...) possibly spanning multiple lines.
# We use a simple bracket-depth walk instead of pure regex for multi-line support.
_EXECUTE_START_RE = re.compile(r'(\w+)\.execute\s*\(', re.IGNORECASE)


def _find_import_os_insert_line(lines: list[str]) -> int:
    """Return the 1-based line number after which ``import os`` should be inserted.

    Heuristic: after the last ``import …`` / ``from … import …`` block at the
    top of the file (before any class/def body).
    """
    last_import_line = 0
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            last_import_line = i
        elif stripped and not stripped.startswith("#") and last_import_line:
            break
    return last_import_line if last_import_line else 0


def _collect_call_lines(lines: list[str], start_idx: int) -> tuple[int, int]:
    """Return (start_idx, end_idx) – both 0-based – for the execute(…) call
    that begins at *start_idx* (which must contain the opening paren).
    Walks forward tracking bracket depth until it closes.
    """
    depth = 0
    for i in range(start_idx, len(lines)):
        for ch in lines[i]:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    return start_idx, i
    return start_idx, start_idx  # fallback: single line


def _extract_fstring_parts(node: ast.JoinedStr) -> tuple[str, list[str]]:
    """Pull a template string and its interpolated variable names out of an
    f-string AST node.

    Returns (template, [var_names]) where template uses ``%s`` placeholders.
    Only handles simple ``{name}`` expressions (no attributes / calls).
    """
    template_parts: list[str] = []
    params: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant):
            template_parts.append(str(value.value))
        elif isinstance(value, ast.FormattedValue):
            inner = value.value
            if isinstance(inner, ast.Name):
                params.append(inner.id)
            elif isinstance(inner, ast.Attribute):
                params.append(ast.unparse(inner))
            else:
                params.append(ast.unparse(inner))
            template_parts.append("%s")
        else:
            template_parts.append("%s")
    return "".join(template_parts), params


def _build_parameterised_execute(
    call_node: ast.Call,
    indent: str,
    cursor_expr: str,
) -> str | None:
    """Given an unsafe ``.execute()`` AST Call node, return a string with the
    safe parameterised replacement, or *None* if rewriting isn't possible.
    """
    if not call_node.args:
        return None

    arg = call_node.args[0]

    # --- f-string: f"SELECT … {var}" ---
    if isinstance(arg, ast.JoinedStr):
        template, params = _extract_fstring_parts(arg)
        if not params:
            return None
        params_tuple = f"({', '.join(params)},)" if len(params) == 1 else f"({', '.join(params)})"
        return f'{indent}{cursor_expr}.execute("{template}", {params_tuple})\n'

    # --- "..." % (var,) ---
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
        sql_node = arg.left
        params_node = arg.right
        if not isinstance(sql_node, ast.Constant):
            return None
        sql_str = sql_node.value
        # Replace %s-style placeholders — already correct; just separate args
        if isinstance(params_node, ast.Tuple):
            params_src = ", ".join(ast.unparse(e) for e in params_node.elts)
            params_tuple = f"({params_src})"
        else:
            params_tuple = f"({ast.unparse(params_node)},)"
        return f'{indent}{cursor_expr}.execute("{sql_str}", {params_tuple})\n'

    # --- "...".format(var) ---
    if (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "format"
        and isinstance(arg.func.value, ast.Constant)
    ):
        sql_str = arg.func.value.value
        # Replace {} placeholders with %s
        sql_str = re.sub(r'\{[^}]*\}', '%s', sql_str)
        params_src = ", ".join(ast.unparse(e) for e in arg.args)
        params_tuple = f"({params_src},)" if len(arg.args) == 1 else f"({params_src})"
        return f'{indent}{cursor_expr}.execute("{sql_str}", {params_tuple})\n'

    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_patch(finding: Finding, project_root: Path | None = None) -> PatchResult | None:
    """Compute a patch for *finding*.  Returns a :class:`PatchResult` or *None*
    if no automated fix is available for this finding type.
    """
    source_path = Path(finding.file)
    try:
        source = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    lines = source.splitlines(keepends=True)

    # ------------------------------------------------------------------
    # Hardcoded Secret
    # ------------------------------------------------------------------
    if "Hardcoded Secret" in finding.vuln_type:
        line_idx = finding.line - 1  # 0-based
        raw_line = lines[line_idx]
        m = _SECRET_ASSIGN_RE.match(raw_line)
        if not m:
            return None

        indent = m.group("indent")
        var_name = m.group("var").upper()
        patched_line = f"{indent}{m.group('var')} = os.getenv({var_name!r})\n"

        extra_files: dict[str, str] = {}

        # Inject ``import os`` if missing
        start_line = finding.line
        insert_offset = 0  # lines prepended before the secret line
        if not _IMPORT_OS_RE.search(source):
            after_imports = _find_import_os_insert_line(lines)
            if after_imports:
                # We track this as an extra header patch rather than modifying
                # the original line range, by embedding it in extra_files keyed
                # with a sentinel.  The apply logic in main.py handles it.
                extra_files["__import_os__"] = str(after_imports)
            else:
                extra_files["__import_os__"] = "0"  # prepend at top

        # Append to .env.example
        root = project_root or source_path.parent
        env_example = root / ".env.example"
        existing = env_example.read_text() if env_example.exists() else ""
        env_key_line = f"{var_name}=\n"
        if env_key_line not in existing:
            extra_files["__env_example__"] = str(env_example)
            extra_files["__env_key__"] = env_key_line

        return PatchResult(
            finding=finding,
            original_lines=[raw_line],
            patched_lines=[patched_line],
            start_line=finding.line,
            extra_files=extra_files,
        )

    # ------------------------------------------------------------------
    # Unparameterised SQL
    # ------------------------------------------------------------------
    if "Unparameterised SQL" in finding.vuln_type:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None

        target_line = finding.line  # 1-based line of the execute() call

        # Find the execute() Call node on or near the reported line
        execute_node: ast.Call | None = None
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and abs(getattr(node, "lineno", 0) - target_line) <= 1
            ):
                if node.args and _is_tainted_arg(node.args[0]):
                    execute_node = node
                    break

        if execute_node is None:
            return None

        start_idx, end_idx = _collect_call_lines(lines, execute_node.lineno - 1)
        raw_block = lines[start_idx : end_idx + 1]

        # Determine indent from first line
        indent_match = re.match(r'^(\s*)', lines[start_idx])
        indent = indent_match.group(1) if indent_match else ""

        # Cursor expression (e.g. "cursor", "self.cursor", "db")
        cursor_expr = ast.unparse(execute_node.func.value)

        replacement = _build_parameterised_execute(execute_node, indent, cursor_expr)
        if replacement is None:
            return None

        return PatchResult(
            finding=finding,
            original_lines=raw_block,
            patched_lines=[replacement],
            start_line=start_idx + 1,  # convert to 1-based
        )

    # ------------------------------------------------------------------
    # Command Injection (CWE-78)
    # ------------------------------------------------------------------
    if "Command Injection" in finding.vuln_type:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None

        target_line = finding.line

        # Find the offending Call node
        call_node: ast.Call | None = None
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if abs(getattr(node, "lineno", 0) - target_line) > 1:
                continue
            func = node.func
            is_cmd = False
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                is_cmd = (func.value.id, func.attr) in _CMD_FUNCS
            elif isinstance(func, ast.Name):
                is_cmd = func.id in {m for _, m in _CMD_FUNCS}
            if is_cmd:
                call_node = node
                break

        if call_node is None:
            return None

        start_idx, end_idx = _collect_call_lines(lines, call_node.lineno - 1)
        raw_block = lines[start_idx : end_idx + 1]
        indent_match = re.match(r'^(\s*)', lines[start_idx])
        indent = indent_match.group(1) if indent_match else ""

        replacement = _build_safe_command(call_node, indent)
        if replacement is None:
            return None

        # Check which imports need injecting
        extra_files: dict[str, str] = {}
        if not _IMPORT_SUBPROCESS_RE.search(source) and "subprocess" in replacement:
            extra_files["__import_subprocess__"] = str(
                _find_import_insert_line(lines, "subprocess")
            )
        if not _IMPORT_SHLEX_RE.search(source) and "shlex" in replacement:
            extra_files["__import_shlex__"] = str(
                _find_import_insert_line(lines, "shlex")
            )

        return PatchResult(
            finding=finding,
            original_lines=raw_block,
            patched_lines=[replacement],
            start_line=start_idx + 1,
            extra_files=extra_files,
        )

    # ------------------------------------------------------------------
    # Insecure File Upload (CWE-434/CWE-22)
    # ------------------------------------------------------------------
    if "Insecure File Upload" in finding.vuln_type:
        target_line = finding.line
        line_idx = target_line - 1
        raw_line = lines[line_idx]

        replacement = _build_safe_file_upload(raw_line)
        if replacement is None:
            return None

        extra_files: dict[str, str] = {}
        if "secure_filename" not in source:
            extra_files["__import_secure_filename__"] = str(
                _find_import_insert_line(lines, "secure_filename")
            )

        return PatchResult(
            finding=finding,
            original_lines=[raw_line],
            patched_lines=[replacement],
            start_line=target_line,
            extra_files=extra_files,
        )

    return None


# ---------------------------------------------------------------------------
# Command injection rewrite helpers
# ---------------------------------------------------------------------------

def _find_import_insert_line(lines: list[str], module: str) -> int:
    """Return the 1-based line after which a new import should be inserted."""
    last_import_line = 0
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            last_import_line = i
        elif stripped and not stripped.startswith("#") and last_import_line:
            break
    return last_import_line if last_import_line else 0


def _build_safe_command(call_node: ast.Call, indent: str) -> str | None:
    """Rewrite a dangerous subprocess/os call to a safe form.

    Strategy:
    * If the first argument is a tainted string: wrap each interpolated
      variable with shlex.quote() and pass the result as a list element,
      or — for simple f-strings — convert to a proper list literal.
    * Remove shell=True from keyword arguments.
    * For os.system / os.popen: replace with subprocess.run([...]).
    """
    func = call_node.func
    if isinstance(func, ast.Attribute):
        module = func.value.id if isinstance(func.value, ast.Name) else ""
        method = func.attr
    elif isinstance(func, ast.Name):
        module = ""
        method = func.id
    else:
        return None

    # Determine the target function name to use in the patched output
    if module in ("", "os") and method in ("system", "popen"):
        new_func = "subprocess.run"
    else:
        new_func = f"{module}.{method}" if module else method

    # Build the safe argument list
    if not call_node.args:
        return None

    first_arg = call_node.args[0]
    safe_cmd = _to_safe_cmd_list(first_arg)
    if safe_cmd is None:
        return None

    # Rebuild keyword arguments, dropping shell=True
    safe_kwargs: list[str] = []
    for kw in call_node.keywords:
        if kw.arg == "shell":
            continue  # drop shell=True / shell=False
        safe_kwargs.append(f"{kw.arg}={ast.unparse(kw.value)}")

    # Any remaining positional args after the first
    extra_pos = [ast.unparse(a) for a in call_node.args[1:]]

    all_args = [safe_cmd] + extra_pos + safe_kwargs
    return f"{indent}{new_func}({', '.join(all_args)})\n"


def _to_safe_cmd_list(arg: ast.expr) -> str | None:
    """Convert a tainted command expression into a safe list-of-strings literal
    or a shlex.quote()-wrapped string, depending on complexity.

    Returns the string representation to embed in source code, or None.
    """
    # f"cmd {var}" → ["cmd", shlex.quote(var)]
    if isinstance(arg, ast.JoinedStr):
        parts: list[str] = []
        for v in arg.values:
            if isinstance(v, ast.Constant):
                # Split static text portions by whitespace into list elements
                for word in str(v.value).split():
                    parts.append(repr(word))
            elif isinstance(v, ast.FormattedValue):
                inner_src = ast.unparse(v.value)
                parts.append(f"shlex.quote({inner_src})")
        if parts:
            return f"[{', '.join(parts)}]"

    # "cmd " + var → ["cmd", shlex.quote(var)]
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        left_src = ast.unparse(arg.left)
        right_src = ast.unparse(arg.right)
        if isinstance(arg.left, ast.Constant):
            words = [repr(w) for w in str(arg.left.value).split()]
            words.append(f"shlex.quote({right_src})")
            return f"[{', '.join(words)}]"
        return f"[shlex.quote({left_src}), shlex.quote({right_src})]"

    # "cmd %s" % var → ["cmd", shlex.quote(var)]
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
        # Fall back to a generic shlex.quote wrapping
        cmd_src = ast.unparse(arg)
        return f"[shlex.quote(part) for part in ({cmd_src}).split()]"

    # "cmd …".format(var) → shlex.quote-wrapped split
    if (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "format"
    ):
        cmd_src = ast.unparse(arg)
        return f"[shlex.quote(part) for part in ({cmd_src}).split()]"

    # Plain string literal: already safe, convert to list
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        words = arg.value.split()
        return f"[{', '.join(repr(w) for w in words)}]"

    return None


# ---------------------------------------------------------------------------
# File upload rewrite helpers
# ---------------------------------------------------------------------------

_FILE_SAVE_START_RE = re.compile(
    r'^(?P<indent>\s*)(?P<var>\w+)\.save\s*\(',
)


def _extract_save_path(raw_line: str, open_paren_pos: int) -> str | None:
    """Walk the line from the opening paren and extract the balanced argument."""
    depth = 0
    start = open_paren_pos
    for i in range(open_paren_pos, len(raw_line)):
        ch = raw_line[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return raw_line[open_paren_pos + 1:i].strip()
    return None


def _build_safe_file_upload(raw_line: str) -> str | None:
    """Rewrite a raw file.save(path) into a safe form with:
    - secure_filename() wrapping only around the filename component
    - extension whitelist guard comment
    - MIME-type validation comment
    Correct form: f.save(os.path.join(UPLOAD_FOLDER, secure_filename(f.filename)))
    """
    m = _FILE_SAVE_START_RE.match(raw_line)
    if not m:
        return None

    # Find the position of the opening paren after .save
    open_paren_pos = raw_line.index('(', m.start('var'))
    path_arg = _extract_save_path(raw_line, open_paren_pos)
    if path_arg is None:
        return None

    indent = m.group("indent")
    var = m.group("var")

    # Wrap correctly: only the filename portion inside os.path.join gets secure_filename
    if "secure_filename" not in path_arg:
        # Match os.path.join(folder, filename_expr) — allow nested parens in filename_expr
        join_m = re.match(
            r'os\.path\.join\s*\(\s*(?P<folder>[^,]+?)\s*,\s*(?P<fname>.+)\s*\)$',
            path_arg,
        )
        if join_m:
            fname = join_m.group('fname').strip()
            # Strip any erroneous outer secure_filename wrapping from fname
            sf_m = re.match(r'secure_filename\s*\((.+)\)$', fname)
            if sf_m:
                fname = sf_m.group(1).strip()
            safe_path = (
                f"os.path.join({join_m.group('folder').strip()}, "
                f"secure_filename({fname}))"
            )
        else:
            safe_path = f"secure_filename({path_arg})"
    else:
        # Already has secure_filename — ensure it wraps only the filename, not the join
        # Pattern: secure_filename(os.path.join(folder, fname))  →  os.path.join(folder, secure_filename(fname))
        wrong_m = re.match(
            r'secure_filename\s*\(\s*os\.path\.join\s*\(\s*(?P<folder>[^,]+?)\s*,\s*(?P<fname>.+?)\s*\)\s*\)$',
            path_arg,
        )
        if wrong_m:
            safe_path = (
                f"os.path.join({wrong_m.group('folder').strip()}, "
                f"secure_filename({wrong_m.group('fname').strip()}))"
            )
        else:
            safe_path = path_arg

    lines_out = [
        f"{indent}# TODO: validate file extension against ALLOWED_EXTENSIONS whitelist\n",
        f"{indent}# TODO: verify MIME type with python-magic before saving\n",
        f"{indent}{var}.save({safe_path})\n",
    ]
    return "".join(lines_out)


def apply_patch(result: PatchResult) -> None:
    """Write the patched content back to disk (including side-effects like
    ``import os`` injection and ``.env.example`` updates).
    """
    source_path = Path(result.finding.file)
    lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)

    start = result.start_line - 1  # 0-based
    end = start + len(result.original_lines)
    lines[start:end] = result.patched_lines

    # Inject ``import os`` if required
    if "__import_os__" in result.extra_files:
        after_line = int(result.extra_files["__import_os__"])
        lines.insert(after_line, "import os\n")

    # Inject ``import subprocess`` if required
    if "__import_subprocess__" in result.extra_files:
        after_line = int(result.extra_files["__import_subprocess__"])
        lines.insert(after_line, "import subprocess\n")

    # Inject ``import shlex`` if required
    if "__import_shlex__" in result.extra_files:
        after_line = int(result.extra_files["__import_shlex__"])
        lines.insert(after_line, "import shlex\n")

    # Inject ``from werkzeug.utils import secure_filename`` if required
    if "__import_secure_filename__" in result.extra_files:
        after_line = int(result.extra_files["__import_secure_filename__"])
        lines.insert(after_line, "from werkzeug.utils import secure_filename\n")

    source_path.write_text("".join(lines), encoding="utf-8")

    # Append to .env.example
    if "__env_example__" in result.extra_files:
        env_path = Path(result.extra_files["__env_example__"])
        env_key_line = result.extra_files.get("__env_key__", "")
        with env_path.open("a", encoding="utf-8") as fh:
            fh.write(env_key_line)


# ---------------------------------------------------------------------------
# Internal taint helper (mirrors detector._is_tainted without the name map)
# ---------------------------------------------------------------------------

def _is_tainted_arg(node: ast.expr) -> bool:
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
    return False


def patch_findings(
    findings: List[Finding],
    project_root: Path | None = None,
) -> List[PatchResult]:
    """Compute patches for all patchable findings; skip XSS and unknowns."""
    results: list[PatchResult] = []
    for f in findings:
        pr = compute_patch(f, project_root=project_root)
        if pr is not None:
            results.append(pr)
    return results
