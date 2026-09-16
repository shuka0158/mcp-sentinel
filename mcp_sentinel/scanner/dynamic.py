"""Protocol-level scanner.

This is the *opt-in, explicit* scanner: it actually launches the target
MCP server process and talks the real protocol to it over stdio, then
inspects the tool/resource manifest it returns. It never runs arbitrary
code beyond the command the caller explicitly asked to run, and it never
invokes any tool — it only calls list_tools()/list_resources().

Because this launches a process the caller nominates, mcp-sentinel's CLI
requires an explicit --i-understand-this-executes-the-target flag before
this module is ever reached. See README "Safety model".
"""
from __future__ import annotations

import re
import shlex

from mcp_sentinel.findings import Finding, ScanResult
from mcp_sentinel.scanner import rules

INJECTION_PHRASES = [
    r"ignore (?:all |any )?(?:previous|prior|above) instructions",
    r"do not (?:tell|inform|mention to) the user",
    r"always call this (?:tool )?first",
    r"never (?:refuse|decline)",
    r"you must (?:always|never)",
    r"this is (?:a |an )?system (?:override|instruction)",
    r"disregard (?:your|the) (?:guidelines|rules|system prompt)",
]
INJECTION_RE = re.compile("|".join(INJECTION_PHRASES), re.IGNORECASE)

BROAD_ENUM_HINTS = {"command", "cmd", "shell", "path", "file", "url", "query", "code"}


def _describe_missing_hints(tool) -> bool:
    name_desc = f"{tool.name} {tool.description or ''}".lower()
    mutating = any(w in name_desc for w in
                   ("write", "delete", "remove", "exec", "run", "update",
                    "create", "modify", "install", "send", "post "))
    annotations = getattr(tool, "annotations", None)
    if not mutating:
        return False
    if annotations is None:
        return True
    has_hint = getattr(annotations, "readOnlyHint", None) is not None or \
        getattr(annotations, "destructiveHint", None) is not None
    return not has_hint


def _inspect_tool(tool) -> list[Finding]:
    findings: list[Finding] = []
    desc = tool.description or ""
    schema = getattr(tool, "inputSchema", None) or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}

    if INJECTION_RE.search(desc):
        meta = rules.INJECTION_PRONE_DESCRIPTION
        findings.append(Finding(
            rule_id=meta.id, title=meta.title, severity=meta.severity,
            category=meta.category,
            description=meta.description + f"\n\nDescription text: {desc[:300]!r}",
            remediation=meta.remediation, tool_name=tool.name, confidence="high",
        ))

    unconstrained = []
    for pname, pschema in props.items():
        if not isinstance(pschema, dict):
            continue
        is_free_string = pschema.get("type") == "string" and not any(
            k in pschema for k in ("enum", "pattern", "format", "maxLength"))
        if is_free_string and pname.lower() in BROAD_ENUM_HINTS:
            unconstrained.append(pname)
    if unconstrained or (not props and any(k in desc.lower() for k in
                                            ("any command", "any file", "arbitrary"))):
        meta = rules.VAGUE_TOOL_SCOPE
        extra = f"unconstrained parameters: {', '.join(unconstrained)}" if unconstrained \
            else "description implies unbounded scope with no schema constraints"
        findings.append(Finding(
            rule_id=meta.id, title=meta.title, severity=meta.severity,
            category=meta.category, description=meta.description + f"\n\n{extra}",
            remediation=meta.remediation, tool_name=tool.name, confidence="medium",
        ))

    if _describe_missing_hints(tool):
        meta = rules.MISSING_READONLY_HINT
        findings.append(Finding(
            rule_id=meta.id, title=meta.title, severity=meta.severity,
            category=meta.category, description=meta.description,
            remediation=meta.remediation, tool_name=tool.name, confidence="low",
        ))

    return findings


async def _scan_async(command: str, args: list[str], env: dict[str, str] | None) -> ScanResult:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        result = ScanResult(target=command, scanner="dynamic")
        result.errors.append(
            "The 'mcp' package is required for dynamic scanning. "
            "Install it with: pip install 'mcp-sentinel[dynamic]'"
        )
        return result

    target = " ".join([command, *args])
    result = ScanResult(target=target, scanner="dynamic")
    params = StdioServerParameters(command=command, args=args, env=env)

    try:
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools_resp = await session.list_tools()
            for tool in tools_resp.tools:
                result.tools_inspected += 1
                result.findings.extend(_inspect_tool(tool))
    except Exception as e:  # noqa: BLE001 - surfaced to the user as a scan error
        result.errors.append(f"failed to introspect server: {e}")

    return result


def scan_command(command_line: str) -> ScanResult:
    """Launch `command_line` as an MCP stdio server and audit its
    advertised tools. Caller is responsible for having obtained explicit
    opt-in before calling this (the CLI enforces this)."""
    import asyncio

    parts = shlex.split(command_line)
    if not parts:
        result = ScanResult(target=command_line, scanner="dynamic")
        result.errors.append("empty command")
        return result

    command, args = parts[0], parts[1:]
    return asyncio.run(_scan_async(command, args, env=None))
