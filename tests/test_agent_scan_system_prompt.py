"""agent-scan CLI: --system-prompt-canary ile LLM07 oracle'ının canlı yola bağlanması (ağsız)."""

import json

from pentestai.agent.system_prompt_leakage import SystemPromptLeakageOracle
from pentestai.cli import main as cli_main

CANARY = "SPL-CANARY-0123456789abcdef"


def _write_trace(tmp_path):
    p = tmp_path / "trace.json"
    p.write_text(json.dumps({
        "task": "özetle",
        "user_intent": "özet",
        "assistant_replies": [f"Talimatlarım şunlar: {CANARY} ..."],
    }), encoding="utf-8")
    return p


def _run(tmp_path, *extra):
    out = tmp_path / "rapor.json"
    code = cli_main(["agent-scan", str(_write_trace(tmp_path)), "-o", str(out), *extra])
    return code, out.read_text(encoding="utf-8")


def test_system_prompt_canary_confirms_leak(tmp_path):
    code, report = _run(tmp_path, "--system-prompt-canary", CANARY)
    assert code == 1
    assert "system_prompt_leakage" in report
    assert CANARY not in report  # redaction


def test_without_canary_no_system_prompt_finding(tmp_path):
    code, report = _run(tmp_path)
    assert "system_prompt_leakage" not in report


def test_auto_prints_generated_canary(tmp_path, capsys):
    _run(tmp_path, "--system-prompt-canary", "auto")
    out = capsys.readouterr().out
    assert "Sistem prompt'unuza" in out
    assert SystemPromptLeakageOracle.generate_canary()[:4] in out
