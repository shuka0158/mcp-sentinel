"""mcp-sentinel command-line interface."""
from __future__ import annotations

import sys

import click

from mcp_sentinel import __version__
from mcp_sentinel.findings import Severity
from mcp_sentinel.scanner import report, rules
from mcp_sentinel.scanner.dynamic import scan_command as _scan_command
from mcp_sentinel.scanner.static import scan_path as _scan_path

FORMATS = ("terminal", "json", "sarif", "markdown")
SEVERITY_NAMES = [s.name for s in Severity]


@click.group()
@click.version_option(__version__, prog_name="mcp-sentinel")
def main():
    """mcp-sentinel — a security scanner for MCP servers.

    Point it at a repo before you install it, or at a tool manifest
    before you trust it with your API keys and shell access.
    """


@main.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(FORMATS), default="terminal",
              help="Output format.")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write report to a file instead of stdout (ignored for terminal format).")
@click.option("--fail-on", type=click.Choice(SEVERITY_NAMES), default=None,
              help="Exit non-zero if any finding at or above this severity is present. "
                   "Useful in CI.")
def scan_cmd(path: str, fmt: str, output: str | None, fail_on: str | None):
    """Statically scan a local directory or file of MCP server source code.

    This never executes the target — it only reads and parses source
    files. Safe to run against code you have not reviewed yet.
    """
    result = _scan_path(path)
    _emit(result, fmt, output)
    _maybe_fail(result, fail_on)


@main.command("scan-live")
@click.argument("command_line")
@click.option("--format", "fmt", type=click.Choice(FORMATS), default="terminal")
@click.option("--output", "-o", type=click.Path(), default=None)
@click.option("--fail-on", type=click.Choice(SEVERITY_NAMES), default=None)
@click.option("--i-understand-this-executes-the-target", "confirmed", is_flag=True,
              default=False,
              help="Required. Confirms you understand this launches COMMAND_LINE "
                   "as a real process on this machine.")
def scan_live_cmd(command_line: str, fmt: str, output: str | None,
                   fail_on: str | None, confirmed: bool):
    """Launch an MCP server over stdio and audit its advertised tool manifest.

    COMMAND_LINE is the exact command used to start the server, quoted as
    one argument, e.g.:

        mcp-sentinel scan-live "python server.py" --i-understand-this-executes-the-target

    Unlike `scan`, this actually runs the target process — only the
    protocol handshake and list_tools() are called, no tool is ever
    invoked, but the process itself executes with your privileges. Only
    run this against servers you already trust enough to start.
    """
    if not confirmed:
        click.secho(
            "Refusing to run: scan-live launches the target process on this "
            "machine. Re-run with --i-understand-this-executes-the-target "
            "once you're sure you want to start it.",
            fg="red", err=True,
        )
        sys.exit(2)

    result = _scan_command(command_line)
    _emit(result, fmt, output)
    _maybe_fail(result, fail_on)


@main.command("rules")
def rules_cmd():
    """List every rule mcp-sentinel can raise."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="mcp-sentinel rule catalog")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Title")
    for meta in sorted(rules.RULES.values(), key=lambda m: m.id):
        table.add_row(meta.id, meta.severity.name, meta.category.value, meta.title)
    console.print(table)


def _emit(result, fmt: str, output: str | None):
    if fmt == "terminal":
        report.to_terminal(result)
        return
    text = {
        "json": report.to_json,
        "sarif": report.to_sarif,
        "markdown": report.to_markdown,
    }[fmt](result)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text)
        click.echo(f"Wrote {fmt} report to {output}")
    else:
        click.echo(text)


def _maybe_fail(result, fail_on: str | None):
    if not fail_on:
        return
    threshold = Severity[fail_on].value
    if any(f.severity.value >= threshold for f in result.findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
