"""LLM red (refusal) tespiti — RefusalDetector, propose_hypotheses_ex, Anthropic/Ollama/planner yolu. Ağsız."""
import json
import logging
import sys
import types

import httpx
import pytest

from pentestai.llm.client import AnthropicLLMClient, MockLLMClient, OllamaLLMClient
from pentestai.llm.refusal import LLMRefusalError, RefusalDetector
from pentestai.models import Endpoint
from pentestai.planner import HypothesisGenerator

VALID = ('[{"type":"idor","method":"GET","path_template":"/api/x/{id}","id_param":"id",'
         '"id_location":"path","resource_key":"x","rationale":"r"}]')


@pytest.mark.parametrize("text", [
    "Üzgünüm, bu konuda yardımcı olamam.",
    "I can't help with that request.",
    "I'm sorry, but I cannot assist with unauthorized access to systems.",
    "As an AI, I must follow ethical guidelines.",
    "Bu işlem yetkisiz erişim olduğu için yapamam.",
    '{"hypotheses": [], "reason": "I cannot help with this."}',
    "<think>hmm [x]</think>I won't help with that.",
])
def test_detector_refusal_texts(text):
    v = RefusalDetector().detect(text)
    assert v.refused and v.matched


def test_detector_valid_json_with_cannot_is_not_refusal():
    text = VALID.replace('"rationale":"r"', '"rationale":"attacker cannot see others; I cannot help but test"')
    assert not RefusalDetector().detect(text).refused


@pytest.mark.parametrize("text", ["[]", '{"hypotheses": []}', "", "Hipotez yok."])
def test_detector_empty_without_pattern_is_not_refusal(text):
    assert not RefusalDetector().detect(text).refused


def test_detector_extra_patterns_di():
    assert not RefusalDetector().detect("Politikam gereği hayır.").refused
    assert RefusalDetector(["politikam gereği"]).detect("Politikam gereği hayır.").refused


async def test_ex_refused_vs_no_hypothesis():
    refused = await MockLLMClient(completion="I can't help with that.").propose_hypotheses_ex("x")
    assert refused.refused and refused.hypotheses == [] and refused.refused_by == ["mock"]
    empty = await MockLLMClient(completion='{"hypotheses": []}').propose_hypotheses_ex("x")
    assert not empty.refused and empty.hypotheses == []
    ok = await MockLLMClient(completion=VALID).propose_hypotheses_ex("x")
    assert not ok.refused and len(ok.hypotheses) == 1


async def test_propose_hypotheses_backward_compatible_list():
    client = MockLLMClient(completion="Üzgünüm, yardımcı olamam")
    assert await client.propose_hypotheses("x") == []


async def test_raw_excerpt_is_truncated_and_redacted():
    text = "I can't help. Authorization: Bearer abc.def.ghi " + "x" * 1000
    res = await MockLLMClient(completion=text).propose_hypotheses_ex("x")
    assert len(res.raw_excerpt) <= 300
    assert "abc.def.ghi" not in res.raw_excerpt


def _fake_anthropic(monkeypatch, stop_reason: str, text: str = ""):
    class _Msgs:
        async def create(self, **_kw):
            block = types.SimpleNamespace(type="text", text=text)
            return types.SimpleNamespace(stop_reason=stop_reason, content=[block])

    class _Client:
        messages = _Msgs()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    mod = types.ModuleType("anthropic")
    mod.AsyncAnthropic = _Client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", mod)


async def test_anthropic_stop_reason_refusal(monkeypatch):
    _fake_anthropic(monkeypatch, "refusal")
    client = AnthropicLLMClient("m")
    with pytest.raises(LLMRefusalError):
        await client.complete("s", "u")
    res = await client.propose_hypotheses_ex("x")
    assert res.refused and res.provider == "anthropic" and "refusal" in res.refusal_reason
    assert await client.propose_hypotheses("x") == []


async def test_anthropic_normal_stop_reason(monkeypatch):
    _fake_anthropic(monkeypatch, "end_turn", VALID)
    res = await AnthropicLLMClient("m").propose_hypotheses_ex("x")
    assert not res.refused and len(res.hypotheses) == 1


def _ollama(content: str) -> OllamaLLMClient:
    handler = lambda req: httpx.Response(200, json={"message": {"content": content}})  # noqa: E731
    return OllamaLLMClient(transport=httpx.MockTransport(handler))


async def test_ollama_schema_masked_refusal_detected():
    masked = json.dumps({"hypotheses": [], "reason": "I'm sorry, but I can't help with that."})
    res = await _ollama(masked).propose_hypotheses_ex("x")
    assert res.refused and res.provider == "ollama"


async def test_ollama_empty_without_pattern_is_not_refusal():
    res = await _ollama('{"hypotheses": []}').propose_hypotheses_ex("x")
    assert not res.refused and res.hypotheses == []


async def test_planner_records_refusal_note(caplog):
    eps = [Endpoint(method="GET", path_template="/api/x/{id}")]
    gen = HypothesisGenerator(MockLLMClient(completion="I can't help with that."))
    with caplog.at_level(logging.WARNING):
        hyps = await gen.generate(eps)
    assert hyps and all(h.source == "deterministic" for h in hyps)   # deterministik devam
    assert len(gen.llm_refusals) == 1 and "reddetti" in gen.llm_refusals[0]
    assert "reddetti" in caplog.text


async def test_planner_no_note_when_llm_answers_or_empty():
    eps = [Endpoint(method="GET", path_template="/api/x/{id}")]
    gen = HypothesisGenerator(MockLLMClient(completion='{"hypotheses": []}'))
    await gen.generate(eps)
    assert gen.llm_refusals == []
