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
