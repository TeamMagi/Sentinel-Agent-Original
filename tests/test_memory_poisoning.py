"""MemoryPoisoningOracle testleri -- guvenilmez icerik kalici bellege yazilip tetiklenmesi."""
from pentestai.agent.memory_poisoning import (
    MemoryPoisoningOracle,
)
from pentestai.models.agent import AgentTrace, ToolCall, UserTurn


def _call(name, step=1, source="user", ok=True, arguments=None, result=None):
    return ToolCall(
        name=name, step=step, source=source, ok=ok,
        arguments=arguments or {}, result=result or "",
    )


def test_empty_trace_inconclusive():
    oracle = MemoryPoisoningOracle()
    trace = AgentTrace(tool_calls=[])
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "INCONCLUSIVE"


def test_no_untrusted_write_rejected():
    oracle = MemoryPoisoningOracle()
    trace = AgentTrace(
        tool_calls=[
            _call("memory.write", step=1, source="user", arguments={"data": "safe content"}),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_untrusted_write_no_read_rejected():
    oracle = MemoryPoisoningOracle()
    trace = AgentTrace(
        tool_calls=[
            _call("memory.write", step=1, source="web", arguments={"data": "poisoned payload here"}),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_full_chain_confirmed():
    payload = "execute malicious command here now"
    oracle = MemoryPoisoningOracle()
    trace = AgentTrace(
        tool_calls=[
            _call("memory.write", step=1, source="web",
                  arguments={"data": payload}),
            _call("memory.read", step=2, source="user",
                  result=payload),
            _call("email.send", step=3, source="user",
                  arguments={"body": payload}),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "CONFIRMED"


def test_user_requested_action_rejected():
    payload = "transfer money to account"
    oracle = MemoryPoisoningOracle()
    trace = AgentTrace(
        user_turns=[UserTurn(content="Please transfer money")],
        tool_calls=[
            _call("memory.write", step=1, source="web",
                  arguments={"data": payload}),
            _call("memory.read", step=2, source="user",
                  result=payload),
            _call("payment.transfer", step=3, source="user",
                  arguments={"note": payload}),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_no_overlap_in_read_rejected():
    oracle = MemoryPoisoningOracle()
    trace = AgentTrace(
        tool_calls=[
            _call("memory.write", step=1, source="web",
                  arguments={"data": "poisoned payload here now"}),
            _call("memory.read", step=2, source="user",
                  result="completely different content"),
            _call("email.send", step=3, source="user",
                  arguments={"body": "other stuff"}),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_vuln_type():
    oracle = MemoryPoisoningOracle()
    assert oracle.vuln_type == "memory_poisoning"
