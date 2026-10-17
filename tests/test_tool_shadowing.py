"""ToolShadowingOracle icin unit testler."""
from pentestai.agent.tool_shadowing import KNOWN_TOOLS, ToolShadowingOracle, find_shadow
from pentestai.models.agent import AgentTrace, ToolCall


def test_empty_trace_inconclusive():
    oracle = ToolShadowingOracle()
    trace = AgentTrace(tool_calls=[])
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "INCONCLUSIVE"


def test_all_legitimate_tools_rejected():
    oracle = ToolShadowingOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", arguments={"url": "test"}, ok=True, step=1),
            ToolCall(name="fs.read", arguments={"path": "x"}, ok=True, step=2),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_typosquat_detected_confirmed():
    oracle = ToolShadowingOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", arguments={"url": "test"}, ok=True, step=1),
            ToolCall(name="http.p0st", arguments={"data": "x"}, ok=True, step=2),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "CONFIRMED"
    assert any("http.p0st" in m for m in finding.evidence.leaked_markers)


def test_separator_change_detected():
    oracle = ToolShadowingOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="email.send", arguments={"to": "x"}, ok=True, step=1),
            ToolCall(name="email_send", arguments={"to": "y"}, ok=True, step=2),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "CONFIRMED"


def test_no_negative_control_inconclusive():
    oracle = ToolShadowingOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.p0st", arguments={"data": "x"}, ok=True, step=1),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "INCONCLUSIVE"


def test_completely_different_name_rejected():
    oracle = ToolShadowingOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", arguments={"url": "test"}, ok=True, step=1),
            ToolCall(name="custom_xyz_action", arguments={}, ok=True, step=2),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_failed_calls_ignored():
    oracle = ToolShadowingOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.p0st", arguments={"data": "x"}, ok=False, step=1),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "INCONCLUSIVE"


def test_custom_known_tools():
    oracle = ToolShadowingOracle(known_tools=("my.tool",))
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="my.tool", arguments={}, ok=True, step=1),
            ToolCall(name="my.tooi", arguments={}, ok=True, step=2),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "CONFIRMED"


def test_find_shadow_exact_match_returns_none():
    assert find_shadow("http.get", KNOWN_TOOLS) is None


def test_find_shadow_typosquat_returns_match():
    result = find_shadow("http.p0st", KNOWN_TOOLS)
    assert result == "http.post"


def test_find_shadow_unrelated_returns_none():
    result = find_shadow("totally_different_tool_name", KNOWN_TOOLS)
    assert result is None


def test_vuln_type():
    oracle = ToolShadowingOracle()
    assert oracle.vuln_type == "tool_shadowing"


def test_tool_shadowing_classification():
    from pentestai.classify import assign_all
    oracle = ToolShadowingOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", arguments={"url": "test"}, ok=True, step=1),
            ToolCall(name="http.p0st", arguments={"data": "x"}, ok=True, step=2),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assign_all([finding])
    assert finding.cwe == "CWE-349"
    assert finding.severity == "High"


def test_scanner_includes_tool_shadowing():
    from pentestai.agent.trace_scanner import AgentTraceScanner
    scanner = AgentTraceScanner()
    assert scanner.predicate_count == 9
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", arguments={"url": "test"}, ok=True, step=1),
            ToolCall(name="http.p0st", arguments={"data": "x"}, ok=True, step=2),
        ]
    )
    findings = scanner.scan(trace)
    types = [f.type for f in findings if f.verdict == "CONFIRMED"]
    assert "tool_shadowing" in types
