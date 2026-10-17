"""ExcessiveAutonomyOracle testleri -- kullanici onaysiz ardisik hassas islem denetler."""
from pentestai.agent.excessive_autonomy import (
    DEFAULT_AUTONOMY_THRESHOLD,
    ExcessiveAutonomyOracle,
    SENSITIVE_TOOLS,
)
from pentestai.models.agent import AgentTrace, ToolCall, UserTurn


def _call(name: str, step: int = 1) -> ToolCall:
    return ToolCall(name=name, arguments={}, ok=True, step=step)


def test_empty_trace_inconclusive():
    oracle = ExcessiveAutonomyOracle()
    trace = AgentTrace(tool_calls=[])
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "INCONCLUSIVE"


def test_no_sensitive_calls_rejected():
    oracle = ExcessiveAutonomyOracle()
    trace = AgentTrace(
        tool_calls=[_call("http.get"), _call("fs.read", step=2)]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_below_threshold_rejected():
    oracle = ExcessiveAutonomyOracle(threshold=3)
    trace = AgentTrace(
        tool_calls=[
            _call("http.get"),
            _call("http.post", step=2),
            _call("http.put", step=3),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_above_threshold_with_safe_confirmed():
    oracle = ExcessiveAutonomyOracle(threshold=2)
    trace = AgentTrace(
        tool_calls=[
            _call("http.get"),
            _call("http.post", step=2),
            _call("http.put", step=3),
            _call("http.delete", step=4),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "CONFIRMED"


def test_user_turn_resets_streak():
    oracle = ExcessiveAutonomyOracle(threshold=3)
    trace = AgentTrace(
        user_turns=[UserTurn(content="ok devam", step=3)],
        tool_calls=[
            _call("http.post", step=1),
            _call("http.put", step=2),
            _call("http.get", step=4),
            _call("http.post", step=5),
            _call("http.put", step=6),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_all_sensitive_no_safe_inconclusive():
    oracle = ExcessiveAutonomyOracle(threshold=2)
    trace = AgentTrace(
        tool_calls=[
            _call("http.post", step=1),
            _call("http.put", step=2),
            _call("http.delete", step=3),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "INCONCLUSIVE"


def test_custom_threshold():
    oracle = ExcessiveAutonomyOracle(threshold=1)
    trace = AgentTrace(
        tool_calls=[
            _call("http.get"),
            _call("http.post", step=2),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "CONFIRMED"


def test_failed_calls_not_counted():
    oracle = ExcessiveAutonomyOracle(threshold=2)
    trace = AgentTrace(
        tool_calls=[
            _call("http.get"),
            ToolCall(name="http.post", arguments={}, ok=False, step=2),
            _call("http.put", step=3),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_vuln_type():
    oracle = ExcessiveAutonomyOracle()
    assert oracle.vuln_type == "excessive_autonomy"
