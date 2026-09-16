from pathlib import Path

from mcp_sentinel.scanner.static import scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def _rule_ids(result):
    return {f.rule_id for f in result.findings}


def test_vulnerable_fixture_triggers_every_expected_rule():
    result = scan_path(str(FIXTURES / "vulnerable_server.py"))
    ids = _rule_ids(result)

    expected = {
        "MCP001",  # subprocess shell=True
        "MCP002",  # os.popen
        "MCP003",  # eval on non-literal
        "MCP010",  # unsanitized path param
        "MCP011",  # ../ literal
        "MCP020",  # unsanitized url param
        "MCP021",  # http:// literal
        "MCP030",  # hardcoded AWS key
        "MCP040",  # pickle.loads
        "MCP041",  # yaml.load unsafe
    }
    missing = expected - ids
    assert not missing, f"rules failed to fire: {missing} (got {ids})"


def test_safe_fixture_has_no_high_or_critical_findings():
    result = scan_path(str(FIXTURES / "safe_server.py"))
    bad = [f for f in result.findings if f.severity.name in ("CRITICAL", "HIGH")]
    assert not bad, f"unexpected high-severity findings on safe code: {bad}"


def test_risk_score_and_grade_are_consistent():
    vuln = scan_path(str(FIXTURES / "vulnerable_server.py"))
    safe = scan_path(str(FIXTURES / "safe_server.py"))
    assert vuln.risk_score > safe.risk_score
    assert vuln.grade in ("D", "F")
    assert safe.grade in ("A", "B")


def test_scan_directory_walks_all_files():
    result = scan_path(str(FIXTURES))
    assert result.files_scanned >= 2


def test_secret_snippet_is_redacted():
    result = scan_path(str(FIXTURES / "vulnerable_server.py"))
    secret_findings = [f for f in result.findings if f.rule_id == "MCP030"]
    assert secret_findings
    for f in secret_findings:
        assert "AKIA" not in (f.snippet or "")


def test_hardcoded_line_numbers_point_at_the_right_line():
    result = scan_path(str(FIXTURES / "vulnerable_server.py"))
    subprocess_findings = [f for f in result.findings if f.rule_id == "MCP001"]
    assert len(subprocess_findings) == 1
    assert subprocess_findings[0].line == 14
