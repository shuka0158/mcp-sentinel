import sys
from pathlib import Path

import pytest

mcp_sdk = pytest.importorskip("mcp", reason="mcp SDK not installed (pip install 'mcp-sentinel[dynamic]')")

from mcp_sentinel.scanner.dynamic import scan_command

FIXTURE = Path(__file__).parent / "fixtures" / "live_server.py"


def test_scan_command_flags_the_overbroad_injection_prone_tool():
    result = scan_command(f"{sys.executable} {FIXTURE}")

    assert not result.errors, result.errors
    assert result.tools_inspected == 2

    ids_by_tool: dict[str, set[str]] = {}
    for f in result.findings:
        ids_by_tool.setdefault(f.tool_name, set()).add(f.rule_id)

    assert {"MCP100", "MCP101", "MCP102"} <= ids_by_tool.get("run_command", set())
    assert "get_weather" not in ids_by_tool
