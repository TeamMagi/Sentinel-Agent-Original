"""SensitiveDisclosureOracle testleri -- hassas verinin display ciktisina sizmasini denetler."""
from pentestai.agent.sensitive_disclosure import (
    SensitiveDisclosureOracle,
)
from pentestai.models.agent import AgentTrace, ToolCall


def test_empty_trace_inconclusive():
    oracle = SensitiveDisclosureOracle()
    trace = AgentTrace(tool_calls=[])
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "INCONCLUSIVE"


def test_no_display_calls_rejected():
    oracle = SensitiveDisclosureOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", arguments={"url": "test"}, ok=True, step=1),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_display_without_secret_rejected():
    oracle = SensitiveDisclosureOracle(entropy_check=False)
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="display", arguments={"text": "Hello world"}, ok=True, step=1),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_secret_in_display_with_clean_confirmed():
    oracle = SensitiveDisclosureOracle(entropy_check=False)
    trace = AgentTrace(
        tool_calls=[
            ToolCall(
                name="display",
                arguments={"text": "api_key=sk_live_1234567890abcdef1234"},
                ok=True, step=1,
            ),
            ToolCall(
                name="display",
                arguments={"text": "Hello safe content"},
                ok=True, step=2,
            ),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "CONFIRMED"


def test_all_display_leaking_inconclusive():
    oracle = SensitiveDisclosureOracle(entropy_check=False)
    trace = AgentTrace(
        tool_calls=[
            ToolCall(
                name="display",
                arguments={"text": "password=secret123"},
                ok=True, step=1,
            ),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "INCONCLUSIVE"


def test_jwt_in_display():
    oracle = SensitiveDisclosureOracle(entropy_check=False)
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ"
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="log", arguments={"msg": jwt}, ok=True, step=1),
            ToolCall(name="log", arguments={"msg": "safe"}, ok=True, step=2),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "CONFIRMED"


def test_failed_calls_ignored():
    oracle = SensitiveDisclosureOracle(entropy_check=False)
    trace = AgentTrace(
        tool_calls=[
            ToolCall(
                name="display",
                arguments={"text": "api_key=secret"},
                ok=False, step=1,
            ),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "REJECTED"


def test_custom_display_tools():
    oracle = SensitiveDisclosureOracle(display_tools=("output",), entropy_check=False)
    trace = AgentTrace(
        tool_calls=[
            ToolCall(
                name="output",
                arguments={"data": "password=hunter2"},
                ok=True, step=1,
            ),
            ToolCall(
                name="output",
                arguments={"data": "clean"},
                ok=True, step=2,
            ),
        ]
    )
    finding = oracle.run(trace, finding_id="f1")
    assert finding.verdict == "CONFIRMED"


def test_vuln_type():
    oracle = SensitiveDisclosureOracle()
    assert oracle.vuln_type == "sensitive_disclosure"
