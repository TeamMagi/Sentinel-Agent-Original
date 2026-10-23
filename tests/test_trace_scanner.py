"""AgentTraceScanner testleri -- tum predicate'leri tek cagriyla calistiran glue layer."""
from pentestai.agent.trace_scanner import AgentTraceScanner
from pentestai.models.agent import AgentTrace, DeclaredManifest, ToolCall, UserTurn


def _call(name: str, step: int = 1, **kwargs) -> ToolCall:
    return ToolCall(name=name, arguments=kwargs, ok=True, step=step)


def test_predicate_count():
    scanner = AgentTraceScanner()
    assert scanner.predicate_count == 12


def test_empty_trace_returns_findings():
    scanner = AgentTraceScanner()
    trace = AgentTrace(tool_calls=[])
    findings = scanner.scan(trace)
    assert len(findings) == 12
    assert all(f.id.startswith("A-") for f in findings)


def test_findings_are_classified():
    scanner = AgentTraceScanner()
    trace = AgentTrace(tool_calls=[_call("http.get", url="test")])
    findings = scanner.scan(trace)
    for f in findings:
        assert f.cwe is not None or f.severity is not None


def test_scan_confirmed_only():
    scanner = AgentTraceScanner()
    trace = AgentTrace(
        user_turns=[UserTurn(content="Show me data")],
        tool_calls=[
            _call("email.send", step=1, to="x@x.com", body="data"),
        ]
    )
    confirmed = scanner.scan_confirmed_only(trace)
    assert all(f.verdict == "CONFIRMED" for f in confirmed)
    types = [f.type for f in confirmed]
    assert "confused_deputy" in types


def test_custom_predicates():
    from pentestai.agent.tool_shadowing import ToolShadowingOracle
    scanner = AgentTraceScanner(predicates=[ToolShadowingOracle()])
    assert scanner.predicate_count == 1
    trace = AgentTrace(
        tool_calls=[
            _call("http.get", step=1, url="test"),
            _call("http.p0st", step=2, data="x"),
        ]
    )
    findings = scanner.scan(trace)
    assert len(findings) == 1
    assert findings[0].verdict == "CONFIRMED"


def test_canary_passed_to_exfiltration():
    scanner = AgentTraceScanner(canary="CANARY_TEST_123")
    trace = AgentTrace(
        tool_calls=[
            _call("http.post", step=1, body="CANARY_TEST_123"),
        ]
    )
    findings = scanner.scan(trace)
    exfil = [f for f in findings if f.type == "exfiltration"]
    assert len(exfil) == 1
    assert exfil[0].verdict == "CONFIRMED"


def test_role_passed_to_privilege_escalation():
    scanner = AgentTraceScanner(role="viewer")
    trace = AgentTrace(
        tool_calls=[
            _call("http.get", step=1),
            _call("fs.write", step=2, path="data.txt"),
        ]
    )
    findings = scanner.scan(trace)
    pe = [f for f in findings if f.type == "privilege_escalation"]
    assert len(pe) == 1
    assert pe[0].verdict == "CONFIRMED"


def test_manifest_passed_to_deviation():
    manifest = DeclaredManifest(allowed_tools=("http.get",))
    scanner = AgentTraceScanner(manifest=manifest)
    trace = AgentTrace(
        tool_calls=[
            _call("http.get", step=1),
            _call("email.send", step=2, to="x"),
        ]
    )
    findings = scanner.scan(trace)
    md = [f for f in findings if f.type == "manifest_deviation"]
    assert len(md) == 1
    assert md[0].verdict == "CONFIRMED"


def test_finding_ids_sequential():
    scanner = AgentTraceScanner()
    trace = AgentTrace(tool_calls=[_call("http.get")])
    findings = scanner.scan(trace)
    ids = [f.id for f in findings]
    expected = [f"A-{i:03d}" for i in range(1, 13)]
    assert ids == expected


