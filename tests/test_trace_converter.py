from pentestai.agent.trace_converter import convert_tool_call, convert_trace
from pentestai.models import AgentTrace, ToolCall


def test_convert_tool_call():
    tc = ToolCall(name='http.post', args={'url': 'test'}, output='ok', source='agent', turn=3)
    result = convert_tool_call(tc)
    assert result.name == 'http.post'
    assert result.arguments == {'url': 'test'}
    assert result.result == 'ok'
    assert result.source == 'tool'
    assert result.step == 3

def test_convert_trace():
    simple = AgentTrace(task='find bugs', user_intent='scan', calls=[ToolCall(name='http.get', args={}, turn=1)])
    rich = convert_trace(simple, target='agent1')
    assert len(rich.user_turns) == 1
    assert len(rich.tool_calls) == 1
    assert rich.target == 'agent1'

def test_source_map_untrusted_content():
    tc = ToolCall(name='web.fetch', args={'url': 'test'}, source='untrusted_content', turn=1)
    result = convert_tool_call(tc)
    assert result.source == 'web'

def test_source_map_has_expanded_keys():
    from pentestai.agent.trace_converter import SOURCE_MAP
    assert SOURCE_MAP["web"] == "web"
    assert SOURCE_MAP["email"] == "email"
    assert SOURCE_MAP["file"] == "file"
    assert SOURCE_MAP["human"] == "user"
    assert SOURCE_MAP["assistant"] == "tool"
    assert SOURCE_MAP["external"] == "web"
    assert SOURCE_MAP["system"] == "system"


def test_source_map_unknown_falls_back():
    from pentestai.agent.trace_converter import SOURCE_MAP
    assert SOURCE_MAP.get("some_random_source", "unknown") == "unknown"

def test_convert_trace_empty():
    simple = AgentTrace(task='', user_intent='', calls=[])
    rich = convert_trace(simple)
    assert len(rich.user_turns) == 0
    assert len(rich.tool_calls) == 0
    assert rich.target == ''

def test_convert_trace_preserves_output():
    tc = ToolCall(name='fs.read', args={'path': '/etc/passwd'}, output='root:x:0:0', turn=1)
    result = convert_tool_call(tc)
    assert result.result == 'root:x:0:0'
    assert result.arguments == {'path': '/etc/passwd'}
