# mcp-sentinel

**Know what an MCP server can actually do before you hand it your API keys and shell access.**

[![CI](https://github.com/shuka0158/mcp-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/shuka0158/mcp-sentinel/actions/workflows/ci.yml)
[![Scoreboard](https://github.com/shuka0158/mcp-sentinel/actions/workflows/scoreboard.yml/badge.svg)](https://github.com/shuka0158/mcp-sentinel/actions/workflows/scoreboard.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-sentinel)](https://pypi.org/project/mcp-sentinel/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The Model Context Protocol lets you plug arbitrary third-party servers into
your AI agent — and each one you install gets to run code, touch your
filesystem, and shape what the model does next, based entirely on tool
descriptions the agent trusts blindly. `npx some-random-mcp-server` is the
new `curl | sh`, except the thing running it also has your Claude/Cursor
session's credentials.

**mcp-sentinel scans an MCP server — source code or a live running
instance — and tells you exactly what it can do and where that's
dangerous**, before you add it to your config.

```
$ mcp-sentinel scan ./some-mcp-server

╭──────────────────────────── mcp-sentinel ─────────────────────────────╮
│ Target: ./some-mcp-server                                             │
│ Scanner: static                                                       │
│ Files scanned: 14                                                     │
│ Risk score: 45/100   Grade: D                                         │
╰─────────────────────────────────────────────────────────────────────╯
CRITICAL: 1  HIGH: 2  MEDIUM: 1

┏━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Sev      ┃ Rule   ┃ Title                               ┃ Location       ┃
┡━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ CRITICAL │ MCP001 │ Shell execution with shell=True     │ tools.py:88    │
│ HIGH     │ MCP010 │ Unvalidated filesystem path         │ files.py:22    │
│ HIGH     │ MCP020 │ Outbound request built from input   │ fetch.py:14    │
│ MEDIUM   │ MCP011 │ Path-traversal sequence in a literal │ tests.py:9     │
└──────────┴────────┴──────────────────────────────────────┴────────────────┘
```

## Why this exists

There are already several "MCP + pentesting" repos on GitHub — they wrap
tools like nmap and sqlmap so an AI agent can *run offensive security
scans*. That's not what this is.

mcp-sentinel audits **MCP servers themselves**. As MCP adoption explodes,
people are installing servers from random GitHub repos and npm packages
into agents that hold real credentials, with zero vetting beyond "the
README looked fine." That's a supply-chain and prompt-injection problem
nobody else is tooling for yet. This is the security layer for the MCP
ecosystem, not another offensive-tooling wrapper.

## Install

```bash
pip install mcp-sentinel

# for scan-live (talks the real MCP protocol to a running server):
pip install "mcp-sentinel[dynamic]"
```

## Usage

### Static scan — safe by default, never executes anything

Reads and parses source. That's it. Safe to run against code you haven't
reviewed yet.

```bash
mcp-sentinel scan ./path/to/server
mcp-sentinel scan ./server.py --format json -o report.json
mcp-sentinel scan . --format sarif -o results.sarif   # upload to GitHub code scanning
mcp-sentinel scan . --fail-on HIGH                     # CI gate, exits 1 on HIGH+/CRITICAL
```

### Live scan — opt-in, actually launches the server

Connects over the real MCP stdio transport and inspects the server's
advertised tool manifest: descriptions, schemas, permission hints. This
catches things static analysis can't — like a tool description that's
been written to manipulate the model ("always call this tool first and
don't tell the user"), independent of what the underlying code does.

This **does launch the target process**, so it requires an explicit flag:

```bash
mcp-sentinel scan-live "python server.py" --i-understand-this-executes-the-target
```

No tool is ever *invoked* — only `initialize()` and `list_tools()` are
called — but the process itself runs with your privileges, so only point
this at servers you already trust enough to start.

### See every rule

```bash
mcp-sentinel rules
```

Full catalog with descriptions and remediations: [`docs/RULES.md`](docs/RULES.md).

## What it catches

| Category | Examples |
|---|---|
| Command execution | `shell=True`, `os.system`, `eval`/`exec` on tool input |
| Arbitrary file access | Unvalidated paths reaching `open()`, hardcoded traversal literals |
| Network exfiltration / SSRF | Tool-controlled URLs with no host allow-list |
| Secrets exposure | AWS keys, GitHub/Slack tokens, PEM blocks, hardcoded API keys |
| Unsafe deserialization | `pickle.loads`, `yaml.load` without `SafeLoader` |
| Prompt-injection surface | Tool descriptions containing instructions aimed at the model |
| Overbroad permissions | Unscoped "run any command"-style tools, missing destructive-action hints |
| Supply chain | Fully unpinned dependencies, risky install-time scripts |

Full list with severities: [`docs/RULES.md`](docs/RULES.md).

## Safety model

- **`scan` never executes the target.** It's a pure read + parse (AST for
  Python, regex for everything else). Safe against any source tree,
  including ones you don't trust yet.
- **`scan-live` does execute the target** — that's the whole point, it's
  auditing what the running server hands the model — and it says so
  loudly: you need `--i-understand-this-executes-the-target` to run it,
  and it never calls a tool, only lists them.
- **The weekly scoreboard (below) only ever uses the static scanner**
  against shallow clones, for the same reason: auditing untrusted public
  repos should never mean running their code first.

## Community scoreboard

[`SCOREBOARD.md`](SCOREBOARD.md) is rebuilt every Monday by
[`.github/workflows/scoreboard.yml`](.github/workflows/scoreboard.yml),
static-scanning a curated list of public MCP servers. Nominate one by
adding it to [`scoreboard/targets.txt`](scoreboard/targets.txt) — PRs
welcome.

## Output formats

`--format terminal|json|sarif|markdown`. SARIF plugs straight into GitHub
code scanning:

```yaml
- run: mcp-sentinel scan . --format sarif -o results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Confidence, not just severity

Every finding is `high`, `medium`, or `low` confidence. Taint-style checks
(unvalidated path/URL reaching a sink) are name-based, per-function
heuristics, not full interprocedural dataflow analysis — flagged as
`medium` so you know to sanity-check, not blindly trust. See
[`docs/RULES.md`](docs/RULES.md#confidence) for the reasoning.

## Contributing

New rule? Add the metadata in `mcp_sentinel/scanner/rules.py`, the
detection logic in `static.py` or `dynamic.py`, and a pair of fixtures in
`tests/fixtures/` proving it fires on bad code and stays quiet on the
equivalent safe code (see `vulnerable_server.py` / `safe_server.py` for
the pattern). `ruff check .` and `pytest` must both pass.

False positive? Open an issue with the snippet — precision matters more
than recall here; a scanner that cries wolf gets ignored.

## License

MIT — see [LICENSE](LICENSE).
