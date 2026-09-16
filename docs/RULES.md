# Rule catalog

Run `mcp-sentinel rules` to print this list from the tool itself — it's
generated from the same source, so it never drifts out of date.

## Static scanner (`mcp-sentinel scan`)

| ID | Severity | Category | What it catches |
|---|---|---|---|
| MCP001 | CRITICAL | command-execution | `subprocess.*(..., shell=True)` |
| MCP002 | CRITICAL | command-execution | `os.system()` / `os.popen()` |
| MCP003 | CRITICAL | command-execution | `eval()`/`exec()` on a non-literal expression |
| MCP010 | HIGH | arbitrary-file-access | A path-like tool parameter reaches `open()`/`Path()`/`os.remove()`/etc. with no `realpath`/`abspath`/`commonpath` check in the function |
| MCP011 | MEDIUM | arbitrary-file-access | A `../../`-style literal found in source |
| MCP020 | HIGH | network-exfiltration | A URL-like tool parameter reaches an HTTP client call with no host allow-list check |
| MCP021 | LOW | insecure-transport | A hardcoded `http://` literal (excluding localhost) |
| MCP030 | CRITICAL | secrets-exposure | AWS keys, GitHub/Slack tokens, PEM private key blocks, generic `api_key = "..."` assignments |
| MCP040 | HIGH | unsafe-deserialization | `pickle.load`/`pickle.loads` |
| MCP041 | HIGH | unsafe-deserialization | `yaml.load()` without `Loader=yaml.SafeLoader` |
| MCP200 | LOW | supply-chain | Unpinned dependency (`requirements.txt` without `==`, `package.json` with `^`/`~`/`latest`) |
| MCP201 | MEDIUM | supply-chain | Non-trivial logic in a `postinstall` script |

## Protocol scanner (`mcp-sentinel scan-live`)

These require actually connecting to a running server and reading its
advertised tool manifest — they can't be seen from source alone (the
manifest can differ from the code, and matters because it's what the
model actually reads).

| ID | Severity | Category | What it catches |
|---|---|---|---|
| MCP100 | MEDIUM | overbroad-permissions | A tool description/schema implies unbounded scope (`"run any command"`) or has an unconstrained free-text `command`/`path`/`url`-style parameter |
| MCP101 | MEDIUM | prompt-injection-surface | A tool/resource description contains imperative language aimed at the model itself ("ignore previous instructions", "always call this first", "do not tell the user") |
| MCP102 | LOW | overbroad-permissions | A tool that looks mutating (write/delete/exec/etc.) has no `readOnlyHint`/`destructiveHint` annotation for hosts to gate on |

## Confidence

Every finding carries a `confidence` of `high`, `medium`, or `low`.
Taint-tracking findings (MCP010, MCP020) are heuristic and per-function —
they're `medium` confidence because mcp-sentinel does shallow, name-based
tracking, not full interprocedural dataflow analysis. Treat `low`-confidence
findings as "worth a human look", not "definitely broken".

## Adding a rule

Rules live in `mcp_sentinel/scanner/rules.py` as metadata, with the actual
detection logic in `static.py` (AST/regex) or `dynamic.py` (manifest
inspection). See `tests/fixtures/vulnerable_server.py` /
`tests/fixtures/safe_server.py` for the pattern used to prove a rule fires
on bad code and stays quiet on the equivalent safe code — new rules should
add both.
