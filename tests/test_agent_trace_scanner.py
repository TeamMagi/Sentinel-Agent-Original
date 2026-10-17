from pentestai.agent.privilege_escalation import PrivilegeEscalationOracle
from pentestai.agent.trace_scanner import AgentTraceScanner
from pentestai.models.agent import AgentTrace, ToolCall, UserTurn


def test_agent_trace_scanner_predicate_count():
    scanner = AgentTraceScanner()
    assert scanner.predicate_count == 9

def test_scan_returns_findings():
    scanner = AgentTraceScanner()
    findings = scanner.scan(AgentTrace(tool_calls=[]))
    assert len(findings) == 9
    assert all(f.id.startswith("A-") for f in findings)

def test_classification_assigned():
    scanner = AgentTraceScanner()
    findings = scanner.scan(AgentTrace(tool_calls=[ToolCall(name="http.get", ok=True, step=1)]))
    assert all(f.cwe is not None and f.severity is not None for f in findings)

def test_confirmed_only():
    scanner = AgentTraceScanner()
    results = scanner.scan_confirmed_only(AgentTrace(tool_calls=[]))
    assert all(r.verdict == "CONFIRMED" for r in results)

def test_privilege_escalation():
    scanner = AgentTraceScanner(role="viewer")
    trace = AgentTrace(tool_calls=[
        ToolCall(name="http.get", ok=True, step=1),
        ToolCall(name="http.post", ok=True, step=2)
    ])
    findings = scanner.scan(trace)
    priv_findings = [f for f in findings if f.type == "privilege_escalation"]
    assert all(f.verdict == "CONFIRMED" for f in priv_findings)

def test_custom_predicates():
    scanner = AgentTraceScanner(predicates=[PrivilegeEscalationOracle()], role="viewer")
    assert scanner.predicate_count == 1

def test_sensitive_disclosure():
    scanner = AgentTraceScanner()
    trace = AgentTrace(tool_calls=[
        ToolCall(name='display', arguments={'text': 'api_key=sk_live_abc123def456ghi789jkl012'}, ok=True, step=1),
        ToolCall(name='display', arguments={'text': 'Hello'}, ok=True, step=2)
    ])
    findings = scanner.scan(trace)
    sd_findings = [f for f in findings if f.type == "sensitive_disclosure"]
    assert all(f.verdict == "CONFIRMED" for f in sd_findings)

def test_excessive_autonomy():
    scanner = AgentTraceScanner()
    trace = AgentTrace(
        user_turns=[UserTurn(step=0)],
        tool_calls=[
            ToolCall(name="http.get", ok=True, step=1),
            ToolCall(name="http.post", ok=True, step=2),
            ToolCall(name="http.put", ok=True, step=3),
            ToolCall(name="fs.write", ok=True, step=4),
            ToolCall(name="http.delete", ok=True, step=5)
        ]
    )
    findings = scanner.scan(trace)
    ea_findings = [f for f in findings if f.type == "excessive_autonomy"]
    assert all(f.verdict == "CONFIRMED" for f in ea_findings)
    assert len(ea_findings) > 0
