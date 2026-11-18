"""FallbackLLMClient — red/hata → sıradaki; hepsi reddederse refused=True. Ağsız."""
import pytest

from pentestai.llm.client import LLMClient, MockLLMClient
from pentestai.llm.fallback import FallbackLLMClient
from pentestai.llm.refusal import LLMRefusalError

VALID = ('[{"type":"idor","method":"GET","path_template":"/api/x/{id}","id_param":"id",'
         '"id_location":"path","resource_key":"x","rationale":"r"}]')


class _ProviderRefuses(LLMClient):
    provider = "bulut"

    async def complete(self, system, user, *, fmt=None):
        raise LLMRefusalError("stop_reason=refusal")


class _Broken(LLMClient):
    provider = "bozuk"

    async def complete(self, system, user, *, fmt=None):
        raise RuntimeError("ağ yok")


async def test_first_refuses_second_answers():
    fb = FallbackLLMClient([MockLLMClient(completion="I can't help with that."),
                            MockLLMClient(completion=VALID)])
    res = await fb.propose_hypotheses_ex("x")
    assert not res.refused and len(res.hypotheses) == 1
    assert res.refused_by == ["mock"] and fb.last_answered_by == "mock"
    assert len(await fb.propose_hypotheses("x")) == 1


async def test_all_refuse_is_flagged_not_silent_empty():
    fb = FallbackLLMClient([_ProviderRefuses(), MockLLMClient(completion="Üzgünüm, yardımcı olamam")])
    res = await fb.propose_hypotheses_ex("x")
    assert res.refused and res.hypotheses == []
    assert res.refused_by == ["bulut", "mock"] and fb.last_answered_by is None


async def test_error_moves_to_next_client():
    fb = FallbackLLMClient([_Broken(), MockLLMClient(completion=VALID)])
    res = await fb.propose_hypotheses_ex("x")
    assert len(res.hypotheses) == 1 and fb.last_errors == ["bozuk: RuntimeError"]


async def test_all_errors_raise():
    with pytest.raises(RuntimeError):
        await FallbackLLMClient([_Broken(), _Broken()]).propose_hypotheses_ex("x")


async def test_complete_falls_through_refusal():
    fb = FallbackLLMClient([_ProviderRefuses(), MockLLMClient(completion="tamam")])
    assert await fb.complete("s", "u") == "tamam"
    assert fb.last_refused_by == ["bulut"]


def test_requires_clients():
    with pytest.raises(ValueError):
        FallbackLLMClient([])
