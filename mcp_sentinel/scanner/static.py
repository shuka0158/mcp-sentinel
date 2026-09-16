"""Static source scanner.

Two layers:
  1. A Python AST visitor that understands actual call structure
     (subprocess shell=True, eval/exec, unsanitized path/URL params,
     unsafe deserialization).
  2. A language-agnostic regex pass over every text file (secrets,
     path-traversal literals, plaintext HTTP, dependency pinning,
     install-time code) so JS/TS/JSON/TOML servers still get useful
     signal even without a full parser.

Static analysis never executes the scanned code.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from mcp_sentinel.findings import Finding, ScanResult
from mcp_sentinel.scanner import rules

PY_GLOB = "*.py"
TEXT_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".toml", ".yaml",
             ".yml", ".txt", ".cfg", ".ini"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", ".mypy_cache", ".pytest_cache", ".tox"}

PATH_PARAM_RE = re.compile(r"(path|file|filename|dir|directory)", re.IGNORECASE)
URL_PARAM_RE = re.compile(r"(url|endpoint|host|uri)", re.IGNORECASE)
TRAVERSAL_RE = re.compile(r"""["'](?:\.\./){2,}""")
HTTP_LITERAL_RE = re.compile(r"""["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"'\s]+["']""")

SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Generic API key assignment", re.compile(
        r"""(?i)\b(api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*["'][A-Za-z0-9_\-/+=]{16,}["']""")),
]


def _iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix in TEXT_EXTS:
            yield p


def _safe_read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


class _PyVisitor(ast.NodeVisitor):
    """Walks a single Python module's AST looking for the call-structure
    based rules. Path/URL-taint tracking is intentionally shallow (per
    function, name-based) — this is a fast heuristic pass, not a full
    dataflow analysis, and is documented as such."""

    def __init__(self, filename: str, source: str):
        self.filename = filename
        self.lines = source.splitlines()
        self.findings: list[Finding] = []

    def _snippet(self, lineno: int) -> str | None:
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()[:160]
        return None

    def _add(self, meta, lineno: int, extra: str | None = None, confidence: str = "high"):
        desc = meta.description + (f"\n\nContext: {extra}" if extra else "")
        self.findings.append(Finding(
            rule_id=meta.id, title=meta.title, severity=meta.severity,
            category=meta.category, description=desc,
            remediation=meta.remediation, file=self.filename, line=lineno,
            snippet=self._snippet(lineno), confidence=confidence,
        ))

    def _call_name(self, node: ast.Call) -> str:
        f = node.func
        if isinstance(f, ast.Attribute):
            base = self._call_name_expr(f.value)
            return f"{base}.{f.attr}" if base else f.attr
        if isinstance(f, ast.Name):
            return f.id
        return ""

    def _call_name_expr(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._call_name_expr(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def visit_Call(self, node: ast.Call):
        name = self._call_name(node)

        if name in {"subprocess.run", "subprocess.call", "subprocess.check_call",
                     "subprocess.check_output", "subprocess.Popen"}:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add(rules.SHELL_TRUE, node.lineno)

        elif name in {"os.system", "os.popen"}:
            self._add(rules.OS_SYSTEM, node.lineno)

        elif name in {"eval", "exec"}:
            if node.args and not isinstance(node.args[0], ast.Constant):
                self._add(rules.DYNAMIC_EXEC, node.lineno,
                          extra=f"{name}() called on a non-literal expression")

        elif name in {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"}:
            self._add(rules.UNSAFE_PICKLE, node.lineno, confidence="medium")

        elif name == "yaml.load":
            has_safe_loader = any(
                kw.arg == "Loader" and self._call_name_expr(kw.value).endswith("SafeLoader")
                for kw in node.keywords
            )
            if not has_safe_loader:
                self._add(rules.UNSAFE_YAML, node.lineno)

        elif name in {"open", "os.remove", "os.unlink", "shutil.rmtree",
                       "Path", "pathlib.Path"}:
            self._check_path_taint(node)

        elif name in {"requests.get", "requests.post", "requests.put",
                       "requests.delete", "requests.request", "httpx.get",
                       "httpx.post", "urllib.request.urlopen", "urlopen"}:
            self._check_url_taint(node)

        self.generic_visit(node)

    def _enclosing_function(self, node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        return getattr(node, "_sentinel_func", None)

    def _check_path_taint(self, node: ast.Call):
        if not node.args:
            return
        arg = node.args[0]
        if isinstance(arg, ast.Constant):
            if isinstance(arg.value, str) and ".." in arg.value:
                self._add(rules.PATH_TRAVERSAL_PATTERN, node.lineno)
            return
        arg_name = self._call_name_expr(arg) if isinstance(arg, (ast.Name, ast.Attribute)) else ""
        func = self._enclosing_function(node)
        if not func or not arg_name:
            return
        param_names = {a.arg for a in func.args.args}
        base_name = arg_name.split(".")[0]
        if base_name in param_names and PATH_PARAM_RE.search(base_name):
            func_src = "\n".join(self.lines[func.lineno - 1:func.end_lineno])
            if not re.search(r"realpath|abspath|resolve\(|commonpath|commonprefix", func_src):
                self._add(rules.UNBOUNDED_PATH, node.lineno,
                          extra=f"parameter '{base_name}' reaches this call unchecked",
                          confidence="medium")

    def _check_url_taint(self, node: ast.Call):
        if not node.args and not node.keywords:
            return
        url_arg = node.args[0] if node.args else next(
            (kw.value for kw in node.keywords if kw.arg == "url"), None)
        if url_arg is None or isinstance(url_arg, ast.Constant):
            return
        arg_name = self._call_name_expr(url_arg) if isinstance(url_arg, (ast.Name, ast.Attribute)) else ""
        func = self._enclosing_function(node)
        if not func or not arg_name:
            return
        param_names = {a.arg for a in func.args.args}
        base_name = arg_name.split(".")[0]
        if base_name in param_names and URL_PARAM_RE.search(base_name):
            func_src = "\n".join(self.lines[func.lineno - 1:func.end_lineno])
            if not re.search(r"allow.?list|ALLOWED_HOSTS|urlparse.*netloc\s*(in|==)", func_src, re.IGNORECASE):
                self._add(rules.UNVALIDATED_URL, node.lineno,
                          extra=f"parameter '{base_name}' reaches this call unchecked",
                          confidence="medium")


def _tag_functions(tree: ast.AST):
    """Annotate every node with its enclosing function, so call-site
    checks can look up the parameter list without re-walking the tree.
    ast.walk() doesn't expose parent context, so this does a manual
    recursive descent instead."""
    def _visit(n: ast.AST, current):
        n._sentinel_func = current
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current = n
            n._sentinel_func = current
        for child in ast.iter_child_nodes(n):
            _visit(child, current)
    _visit(tree, None)


def _scan_python(rel: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=rel)
    except SyntaxError:
        return []
    _tag_functions(tree)
    visitor = _PyVisitor(rel, source)
    visitor.visit(tree)
    return visitor.findings


# Path-traversal literals are only meaningful signal in actual source
# code, where they can plausibly reach a file-access call. In config
# files (tsconfig "extends", tool "include" globs, etc.) a "../../" is
# normal, expected authoring style and not a security finding.
SOURCE_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs"}


def _scan_text_generic(rel: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    check_traversal = Path(rel).suffix in SOURCE_EXTS

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        is_comment = stripped.startswith(("#", "//", "*", "/*"))

        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                meta = rules.HARDCODED_SECRET
                findings.append(Finding(
                    rule_id=meta.id, title=meta.title, severity=meta.severity,
                    category=meta.category,
                    description=meta.description + f"\n\nMatched pattern: {label}",
                    remediation=meta.remediation, file=rel, line=lineno,
                    snippet=re.sub(r"[A-Za-z0-9_\-/+=]{8,}", "***REDACTED***", line.strip())[:160],
                    confidence="medium",
                ))
        if check_traversal and not is_comment and TRAVERSAL_RE.search(line):
            meta = rules.PATH_TRAVERSAL_PATTERN
            findings.append(Finding(
                rule_id=meta.id, title=meta.title, severity=meta.severity,
                category=meta.category, description=meta.description,
                remediation=meta.remediation, file=rel, line=lineno,
                snippet=line.strip()[:160], confidence="low",
            ))
        if HTTP_LITERAL_RE.search(line):
            meta = rules.INSECURE_TRANSPORT
            findings.append(Finding(
                rule_id=meta.id, title=meta.title, severity=meta.severity,
                category=meta.category, description=meta.description,
                remediation=meta.remediation, file=rel, line=lineno,
                snippet=line.strip()[:160], confidence="medium",
            ))
    return findings


def _scan_dependencies(rel: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    meta = rules.UNPINNED_DEPENDENCY

    if rel.endswith("requirements.txt"):
        for lineno, line in enumerate(source.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            if not re.search(r"==\d", line):
                findings.append(Finding(
                    rule_id=meta.id, title=meta.title, severity=meta.severity,
                    category=meta.category, description=meta.description,
                    remediation=meta.remediation, file=rel, line=lineno,
                    snippet=line[:160], confidence="low",
                ))

    elif rel.endswith("package.json"):
        try:
            data = json.loads(source)
        except json.JSONDecodeError:
            return findings
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section) or {}).items():
                # Only flag truly unpinned deps ("*" / "latest" / "x").
                # Caret/tilde semver ranges (^1.2.3, ~1.2.3) are normal,
                # expected practice in the npm ecosystem — the lockfile,
                # not the manifest, is what pins the resolved version.
                if isinstance(ver, str) and re.fullmatch(r"\*|latest|x", ver.strip()):
                    findings.append(Finding(
                        rule_id=meta.id, title=meta.title, severity=meta.severity,
                        category=meta.category, description=meta.description,
                        remediation=meta.remediation, file=rel,
                        snippet=f'"{name}": "{ver}"', confidence="low",
                    ))
        script = (data.get("scripts") or {}).get("postinstall")
        if script:
            im = rules.INSTALL_TIME_CODE
            findings.append(Finding(
                rule_id=im.id, title=im.title, severity=im.severity,
                category=im.category, description=im.description,
                remediation=im.remediation, file=rel,
                snippet=f'postinstall: "{script}"', confidence="medium",
            ))
    return findings


def scan_path(target: str) -> ScanResult:
    root = Path(target).expanduser().resolve()
    result = ScanResult(target=str(root), scanner="static")

    for path in _iter_files(root):
        source = _safe_read(path)
        if source is None:
            result.errors.append(f"could not read {path}")
            continue

        rel = str(path.relative_to(root)) if root.is_dir() else path.name
        result.files_scanned += 1

        if path.suffix == ".py":
            result.findings.extend(_scan_python(rel, source))

        result.findings.extend(_scan_text_generic(rel, source))
        result.findings.extend(_scan_dependencies(rel, source))

    return result
