"""PrivilegeEscalationOracle testleri -- rol tabanli yetki asimi denetler."""
from pentestai.agent.privilege_escalation import (
    PrivilegeEscalationOracle,
)
from pentestai.models.agent import AgentTrace, ToolCall


def _call(name: str, step: int = 1) -> ToolCall:
    return ToolCall(name=name, arguments={}, ok=True, step=step)


def test_unknown_role_rejected():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(tool_calls=[_call("http.get")])
    finding = oracle.run(trace, finding_id="f1", role="nonexistent")
    assert finding.verdict == "REJECTED"


def test_admin_unlimited_rejected():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(tool_calls=[_call("fs.delete")])
    finding = oracle.run(trace, finding_id="f1", role="admin")
    assert finding.verdict == "REJECTED"


def test_empty_trace_inconclusive():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(tool_calls=[])
    finding = oracle.run(trace, finding_id="f1", role="viewer")
    assert finding.verdict == "INCONCLUSIVE"


def test_viewer_within_limits_rejected():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(tool_calls=[_call("http.get"), _call("fs.read", step=2)])
    finding = oracle.run(trace, finding_id="f1", role="viewer")
    assert finding.verdict == "REJECTED"


def test_viewer_escalation_confirmed():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(
        tool_calls=[
            _call("http.get"),
            _call("fs.write", step=2),
        ]
    )
    finding = oracle.run(trace, finding_id="f1", role="viewer")
    assert finding.verdict == "CONFIRMED"


def test_all_unauthorized_no_compliant_inconclusive():
    oracle = PrivilegeEscalationOracle()
    trace = AgentTrace(
        tool_calls=[_call("fs.write"), _call("fs.delete", step=2)]
    )
    finding = oracle.run(trace, finding_id="f1", role="viewer")
    assert finding.verdict == "INCONCLUSIVE"


def test_failed_calls_ignored():
    oracle = PrivilegeEscalationOracle()
    failed = ToolCall(name="fs.write", arguments={}, ok=False, step=1)
    trace = AgentTrace(tool_calls=[failed])
    finding = oracle.run(trace, finding_id="f1", role="viewer")
    assert finding.verdict == "INCONCLUSIVE"


def test_custom_role_permissions():
    custom = {"readonly": ("http.get",)}
    oracle = PrivilegeEscalationOracle(role_permissions=custom)
    trace = AgentTrace(
        tool_calls=[_call("http.get"), _call("http.post", step=2)]
    )
    finding = oracle.run(trace, finding_id="f1", role="readonly")
    assert finding.verdict == "CONFIRMED"


def test_vuln_type():
    oracle = PrivilegeEscalationOracle()
    assert oracle.vuln_type == "privilege_escalation"
