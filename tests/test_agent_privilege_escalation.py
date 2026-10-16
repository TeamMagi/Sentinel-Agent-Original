"""PrivilegeEscalationOracle için unit testler."""
from pentestai.agent.privilege_escalation import PrivilegeEscalationOracle
from pentestai.models.agent import AgentTrace, ToolCall


def test_confirmed_unauthorized_tool():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", ok=True),
            ToolCall(name="http.post", ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1", role="viewer")
    assert result.verdict == "CONFIRMED"


def test_rejected_all_authorized():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", ok=True),
            ToolCall(name="search", ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1", role="viewer")
    assert result.verdict == "REJECTED"


def test_rejected_admin_unlimited():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="fs.write", ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1", role="admin")
    assert result.verdict == "REJECTED"


def test_inconclusive_no_compliant():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.post", ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1", role="viewer")
    assert result.verdict == "INCONCLUSIVE"


def test_inconclusive_empty_trace():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(tool_calls=[])
    result = oracle.run(trace, finding_id="f1", role="viewer")
    assert result.verdict == "INCONCLUSIVE"


def test_prefix_match():
    oracle = PrivilegeEscalationOracle(role_permissions={"custom": ("http",)})
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1", role="custom")
    assert result.verdict == "REJECTED"


def test_custom_permissions_di():
    oracle = PrivilegeEscalationOracle(role_permissions={"restricted": ("search",)})
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="search", ok=True),
            ToolCall(name="http.get", ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1", role="restricted")
    assert result.verdict == "CONFIRMED"
