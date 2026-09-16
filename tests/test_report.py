import json
from pathlib import Path

from mcp_sentinel.scanner import report
from mcp_sentinel.scanner.static import scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def _result():
    return scan_path(str(FIXTURES / "vulnerable_server.py"))


def test_json_report_round_trips():
    result = _result()
    data = json.loads(report.to_json(result))
    assert data["target"].endswith("vulnerable_server.py")
    assert data["risk_score"] == result.risk_score
    assert len(data["findings"]) == len(result.findings)
    assert {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} <= set(data["counts"].keys())


def test_sarif_report_is_well_formed():
    result = _result()
    sarif = json.loads(report.to_sarif(result))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcp-sentinel"
    rule_ids_in_rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
    rule_ids_in_results = {r["ruleId"] for r in run["results"]}
    assert rule_ids_in_results <= rule_ids_in_rules


def test_markdown_report_lists_every_finding():
    result = _result()
    md = report.to_markdown(result)
    assert "# mcp-sentinel report" in md
    for f in result.findings:
        assert f.rule_id in md


def test_empty_result_reports_cleanly():
    from mcp_sentinel.findings import ScanResult
    empty = ScanResult(target="nothing", scanner="static")
    assert "No issues detected" in report.to_markdown(empty)
    assert json.loads(report.to_json(empty))["findings"] == []
