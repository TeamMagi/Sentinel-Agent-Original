"""SensitiveDisclosureOracle icin unit testler."""
from pentestai.agent.sensitive_disclosure import SensitiveDisclosureOracle
from pentestai.models.agent import AgentTrace, ToolCall


def test_confirmed_secret_in_display():
    """Display cagrisinda API key bulundu ve temiz display de var -> CONFIRMED."""
    oracle = SensitiveDisclosureOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="display", arguments={"text": "api_key=sk_live_abc123def456ghi789jkl012"}, ok=True),
            ToolCall(name="display", arguments={"text": "Merhaba dunya"}, ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1")
    assert result.verdict == "CONFIRMED"


def test_rejected_no_secret():
    """Display cagrisinda hassas veri yok -> REJECTED."""
    oracle = SensitiveDisclosureOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="display", arguments={"text": "Merhaba dunya"}, ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1")
    assert result.verdict == "REJECTED"


def test_rejected_no_display_call():
    """Display cagrisi yok -> REJECTED."""
    oracle = SensitiveDisclosureOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="http.get", arguments={"url": "test"}, ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1")
    assert result.verdict == "REJECTED"


def test_inconclusive_empty_trace():
    """Bos trace -> INCONCLUSIVE."""
    oracle = SensitiveDisclosureOracle()
    trace = AgentTrace(tool_calls=[])
    result = oracle.run(trace, finding_id="f1")
    assert result.verdict == "INCONCLUSIVE"


def test_inconclusive_all_displays_have_secrets():
    """Tum display cagrilarinda hassas veri var, negative control yok -> INCONCLUSIVE."""
    oracle = SensitiveDisclosureOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="display", arguments={"text": "password=hunter2"}, ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1")
    assert result.verdict == "INCONCLUSIVE"


def test_jwt_token_detected():
    """JWT token kalibi display'de -> CONFIRMED (negative control ile)."""
    oracle = SensitiveDisclosureOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="log", arguments={"message": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"}, ok=True),
            ToolCall(name="log", arguments={"message": "Islem tamamlandi"}, ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1")
    assert result.verdict == "CONFIRMED"


def test_custom_tools_di():
    """DI ile ozel display tool listesi."""
    oracle = SensitiveDisclosureOracle(display_tools=("custom_output",))
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="custom_output", arguments={"data": "secret_key=abc123xyz"}, ok=True),
            ToolCall(name="custom_output", arguments={"data": "normal bilgi"}, ok=True),
        ]
    )
    result = oracle.run(trace, finding_id="f1")
    assert result.verdict == "CONFIRMED"


def test_entropy_fallback_detects_unknown_secret():
    oracle = SensitiveDisclosureOracle()
    trace = AgentTrace(
        tool_calls=[
            ToolCall(name="display", arguments={"text": "token: xK9mP2vL8nQ5wR3jF7hT1cY6bA4dE0gU"}, ok=True, step=1),
            ToolCall(name="display", arguments={"text": "Hello world"}, ok=True, step=2),
        ]
    )
    result = oracle.run(trace, finding_id="f1")
    assert result.verdict == "CONFIRMED"
