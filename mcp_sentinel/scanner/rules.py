"""Rule catalog: every rule mcp-sentinel can raise, with metadata used both
by the scanners (to build Finding objects) and by `mcp-sentinel rules`
(to print the catalog)."""
from __future__ import annotations

from dataclasses import dataclass

from mcp_sentinel.findings import Category, Severity


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    severity: Severity
    category: Category
    description: str
    remediation: str


RULES: dict[str, RuleMeta] = {}


def _r(id: str, title: str, severity: Severity, category: Category,
       description: str, remediation: str) -> RuleMeta:
    meta = RuleMeta(id, title, severity, category, description, remediation)
    RULES[id] = meta
    return meta


# ---- Command execution -----------------------------------------------
SHELL_TRUE = _r(
    "MCP001", "Shell execution with shell=True",
    Severity.CRITICAL, Category.COMMAND_EXECUTION,
    "A subprocess call is made with shell=True (or an equivalent shell "
    "invocation). If any part of the command is built from tool arguments "
    "supplied by the model, this is a direct path to command injection: "
    "an attacker who can influence the agent's input can get shell access "
    "on the machine running the MCP server.",
    "Use subprocess with a list of arguments and shell=False. If a shell "
    "is genuinely required, strictly allow-list and quote every argument "
    "with shlex.quote() and validate it against an expected pattern first.",
)

OS_SYSTEM = _r(
    "MCP002", "os.system / os.popen usage",
    Severity.CRITICAL, Category.COMMAND_EXECUTION,
    "os.system() or os.popen() runs a string through the shell. Same risk "
    "class as shell=True: any tool argument reaching this call is a "
    "command injection primitive.",
    "Replace with subprocess.run([...], shell=False) using an explicit "
    "argument list, or remove the shell call entirely if not needed.",
)

DYNAMIC_EXEC = _r(
    "MCP003", "eval() / exec() on non-constant input",
    Severity.CRITICAL, Category.COMMAND_EXECUTION,
    "eval() or exec() is called on data that is not a hardcoded string "
    "literal. If tool input (directly or indirectly) reaches this call, "
    "an attacker fully controls code execution inside the server process.",
    "Never eval/exec external input. Use ast.literal_eval() for data "
    "literals, or a proper parser/interpreter with a restricted grammar.",
)

# ---- File access --------------------------------------------------------
UNBOUNDED_PATH = _r(
    "MCP010", "Unvalidated filesystem path from tool input",
    Severity.HIGH, Category.ARBITRARY_FILE_ACCESS,
    "A file is opened/read/written using a path built from tool arguments "
    "without checking it stays inside an allowed root. A model (or a "
    "malicious prompt) can pass '../../etc/passwd'-style paths to read or "
    "overwrite files anywhere the process has permission to touch.",
    "Resolve the path with os.path.realpath() and verify it is a "
    "descendant of an explicit allow-listed root directory before use. "
    "Reject the request otherwise.",
)

PATH_TRAVERSAL_PATTERN = _r(
    "MCP011", "Path-traversal sequence in a string constant",
    Severity.MEDIUM, Category.ARBITRARY_FILE_ACCESS,
    "A literal path containing '..' segments was found, which often "
    "indicates a traversal vector was hardcoded during testing and left "
    "in, or that the code builds paths by string concatenation instead "
    "of safe join+normalize.",
    "Build paths with os.path.join() then normalize and validate against "
    "an allow-listed root; remove any hardcoded traversal sequences.",
)

# ---- Network --------------------------------------------------------
UNVALIDATED_URL = _r(
    "MCP020", "Outbound request to a URL built from tool input",
    Severity.HIGH, Category.NETWORK_EXFILTRATION,
    "An HTTP client call is made to a URL constructed from tool arguments "
    "without host allow-listing. This lets a compromised or manipulated "
    "agent make the server act as an open network proxy — including to "
    "internal/cloud-metadata addresses (SSRF).",
    "Allow-list acceptable hosts/schemes explicitly, and block requests "
    "to link-local, loopback, and cloud metadata ranges "
    "(169.254.169.254 etc.) before making the request.",
)

INSECURE_TRANSPORT = _r(
    "MCP021", "Plaintext HTTP endpoint",
    Severity.LOW, Category.INSECURE_TRANSPORT,
    "An http:// URL literal was found where a network call is made. "
    "Traffic (including any credentials or tool output) is unencrypted.",
    "Use https:// endpoints; if the target genuinely only supports "
    "plaintext HTTP, document why and keep it off any path that carries "
    "secrets.",
)

# ---- Secrets --------------------------------------------------------
HARDCODED_SECRET = _r(
    "MCP030", "Hardcoded credential or API key",
    Severity.CRITICAL, Category.SECRETS_EXPOSURE,
    "A string literal matching a known API key / token / private key "
    "pattern was found in source. Anyone with read access to the repo "
    "(and anyone the code is shared with) gets the credential.",
    "Remove the secret from source, rotate it immediately, and load it "
    "from an environment variable or a secrets manager instead.",
)

# ---- Deserialization --------------------------------------------------------
UNSAFE_PICKLE = _r(
    "MCP040", "pickle.load(s) on untrusted data",
    Severity.HIGH, Category.UNSAFE_DESERIALIZATION,
    "pickle can execute arbitrary code during deserialization. Loading "
    "pickle data derived from tool input or network responses is "
    "equivalent to remote code execution.",
    "Use a data-only format (JSON, msgpack) for anything crossing a "
    "trust boundary. If pickle is unavoidable, sign and verify the "
    "payload before loading it.",
)

UNSAFE_YAML = _r(
    "MCP041", "yaml.load() without a safe Loader",
    Severity.HIGH, Category.UNSAFE_DESERIALIZATION,
    "yaml.load() without SafeLoader can construct arbitrary Python "
    "objects from the input document, similar to pickle.",
    "Use yaml.safe_load() (or yaml.load(x, Loader=yaml.SafeLoader)).",
)

# ---- MCP-protocol-specific: tool manifest issues -------------------------
VAGUE_TOOL_SCOPE = _r(
    "MCP100", "Tool description grants unbounded capability",
    Severity.MEDIUM, Category.OVERBROAD_PERMISSIONS,
    "The tool's description/schema does not constrain what it operates "
    "on (e.g. 'run any command', 'read any file', a free-text path/URL "
    "argument with no pattern or enum). This maximizes blast radius if "
    "the tool is ever invoked with attacker-influenced arguments, and "
    "widens the prompt-injection attack surface for the whole session.",
    "Scope the tool as narrowly as the use case allows: enum/pattern-"
    "constrain arguments, split an 'any command' tool into specific "
    "named operations, and document the exact allowed scope.",
)

INJECTION_PRONE_DESCRIPTION = _r(
    "MCP101", "Tool/resource description contains embedded instructions",
    Severity.MEDIUM, Category.PROMPT_INJECTION_SURFACE,
    "The tool description contains imperative language aimed at the "
    "model itself (e.g. 'ignore previous instructions', 'always call "
    "this first', 'do not tell the user'). Descriptions are read by the "
    "model as part of its context, so this is a vector for the server "
    "(or anyone who can edit its manifest) to manipulate agent behavior.",
    "Keep tool descriptions purely descriptive (what the tool does, its "
    "parameters) and avoid directive language. Treat any MCP server "
    "whose descriptions try to steer model behavior as suspicious.",
)

MISSING_READONLY_HINT = _r(
    "MCP102", "Mutating tool missing a destructive/readOnly annotation",
    Severity.LOW, Category.OVERBROAD_PERMISSIONS,
    "The tool appears to mutate state (its name/description suggests "
    "write/delete/exec) but does not declare MCP annotation hints "
    "(readOnlyHint/destructiveHint). Clients that rely on these hints "
    "to decide when to prompt the user for confirmation cannot do so "
    "correctly for this tool.",
    "Set the appropriate tool annotations (readOnlyHint, destructiveHint, "
    "idempotentHint, openWorldHint) so hosts can gate risky calls behind "
    "user confirmation.",
)

# ---- Supply chain --------------------------------------------------------
UNPINNED_DEPENDENCY = _r(
    "MCP200", "Dependency without a pinned/locked version",
    Severity.LOW, Category.SUPPLY_CHAIN,
    "A dependency is declared without a pinned version or lockfile "
    "entry, allowing a future malicious release to be pulled in "
    "silently on install.",
    "Pin exact versions and commit a lockfile (requirements.txt with "
    "hashes, poetry.lock, package-lock.json, etc.).",
)

INSTALL_TIME_CODE = _r(
    "MCP201", "Arbitrary code runs at install time",
    Severity.MEDIUM, Category.SUPPLY_CHAIN,
    "A setup.py / postinstall script executes non-trivial logic (network "
    "calls, subprocess, file writes) at install time, before any review "
    "of the package's actual runtime behavior happens.",
    "Move logic out of install-time hooks where possible; if unavoidable, "
    "keep it minimal, auditable, and free of network/subprocess calls.",
)


def get(rule_id: str) -> RuleMeta:
    return RULES[rule_id]
