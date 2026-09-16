"""Report rendering: terminal (rich), JSON, SARIF, Markdown."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from mcp_sentinel.findings import ScanResult, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                   Severity.LOW, Severity.INFO]


def to_terminal(result: ScanResult) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    grade_color = {"A": "green", "B": "green", "C": "yellow",
                   "D": "red", "F": "bold red"}[result.grade]

    header = (
        f"[bold]Target:[/bold] {result.target}\n"
        f"[bold]Scanner:[/bold] {result.scanner}\n"
        f"[bold]Files scanned:[/bold] {result.files_scanned}"
        + (f"  [bold]Tools inspected:[/bold] {result.tools_inspected}"
           if result.scanner == "dynamic" else "")
        + f"\n[bold]Risk score:[/bold] {result.risk_score}/100   "
        f"[bold]Grade:[/bold] [{grade_color}]{result.grade}[/{grade_color}]"
    )
    console.print(Panel(header, title="mcp-sentinel", expand=False))

    counts = result.counts()
    console.print(
        "  ".join(
            f"[{s.color}]{s.name}: {counts[s.name]}[/{s.color}]"
            for s in SEVERITY_ORDER if counts[s.name]
        ) or "[green]No findings.[/green]"
    )

    if not result.findings:
        console.print("\n[green]Clean scan — no issues detected.[/green]")
    else:
        table = Table(show_lines=True)
        table.add_column("Sev", width=8)
        table.add_column("Rule")
        table.add_column("Title")
        table.add_column("Location")
        table.add_column("Confidence", width=10)

        ordered = sorted(result.findings, key=lambda f: -f.severity.value)
        for f in ordered:
            table.add_row(
                f"[{f.severity.color}]{f.severity.name}[/{f.severity.color}]",
                f.rule_id, f.title, f.location(), f.confidence,
            )
        console.print(table)

        console.print("\n[bold]Details[/bold]")
        for f in ordered:
            console.print(f"\n[{f.severity.color}]● {f.rule_id} — {f.title}[/{f.severity.color}] "
                          f"([dim]{f.location()}[/dim])")
            if f.snippet:
                console.print(f"  [dim]{f.snippet}[/dim]")
            console.print(f"  {f.description}")
            console.print(f"  [bold]Fix:[/bold] {f.remediation}")

    if result.errors:
        console.print("\n[yellow]Warnings:[/yellow]")
        for e in result.errors:
            console.print(f"  - {e}")


def to_json(result: ScanResult) -> str:
    payload = {
        "target": result.target,
        "scanner": result.scanner,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files_scanned": result.files_scanned,
        "tools_inspected": result.tools_inspected,
        "risk_score": result.risk_score,
        "grade": result.grade,
        "counts": result.counts(),
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.name,
                "category": f.category.value,
                "description": f.description,
                "remediation": f.remediation,
                "file": f.file,
                "line": f.line,
                "snippet": f.snippet,
                "tool_name": f.tool_name,
                "confidence": f.confidence,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2)


_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error",
    Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note",
}


def to_sarif(result: ScanResult) -> str:
    rule_ids = sorted({f.rule_id for f in result.findings})
    from mcp_sentinel.scanner import rules as rule_catalog

    sarif_rules = []
    for rid in rule_ids:
        meta = rule_catalog.get(rid)
        sarif_rules.append({
            "id": meta.id,
            "name": meta.title,
            "shortDescription": {"text": meta.title},
            "fullDescription": {"text": meta.description},
            "help": {"text": meta.remediation},
            "properties": {"category": meta.category.value, "severity": meta.severity.name},
        })

    results = []
    for f in result.findings:
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file or "unknown"},
            }
        }
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.description},
            "locations": [loc],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "mcp-sentinel", "informationUri":
                      "https://github.com/shuka0158/mcp-sentinel", "rules": sarif_rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def to_markdown(result: ScanResult) -> str:
    lines = [
        f"# mcp-sentinel report — `{result.target}`",
        "",
        f"- **Scanner:** {result.scanner}",
        f"- **Files scanned:** {result.files_scanned}",
    ]
    if result.scanner == "dynamic":
        lines.append(f"- **Tools inspected:** {result.tools_inspected}")
    lines += [
        f"- **Risk score:** {result.risk_score}/100",
        f"- **Grade:** {result.grade}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    counts = result.counts()
    for s in SEVERITY_ORDER:
        if counts[s.name]:
            lines.append(f"| {s.name} | {counts[s.name]} |")

    if not result.findings:
        lines += ["", "No issues detected."]
        return "\n".join(lines)

    lines += ["", "## Findings", ""]
    for f in sorted(result.findings, key=lambda f: -f.severity.value):
        lines.append(f"### {f.severity.name} — {f.rule_id} {f.title}")
        lines.append(f"*Location:* `{f.location()}`  *Confidence:* {f.confidence}")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        lines.append(f"**Fix:** {f.remediation}")
        lines.append("")
    return "\n".join(lines)
