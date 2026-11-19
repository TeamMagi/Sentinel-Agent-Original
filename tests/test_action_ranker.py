"""ActionRanker — aday havuzu önceliklendirme (Faz 7).

Ağsız: HeuristicRanker yalnızca WorldModel verisini kullanır; LLMRanker sahte LLM ile
(MockLLM/LLMRefusalError) test edilir. Değişmezler:
  • Ranker havuza aksiyon EKLEYEMEZ (indeks doğrulaması) — scope güvenliği korunur.
  • LLM red/parse hatasında heuristik sıralamaya düşer + red notu bırakır.
  • Havuz batch'ten küçükse LLM çağrılmaz (token tasarrufu).
"""
import pytest

from pentestai.llm.client import LLMClient, MockLLMClient
from pentestai.llm.prompts import PromptBuilder
from pentestai.llm.refusal import LLMRefusalError
from pentestai.models import Endpoint, Observation
from pentestai.orchestrator.actions import EnumerateIds, Probe, RunOracle
from pentestai.orchestrator.agent import AgenticOrchestrator
from pentestai.orchestrator.ranker import (
    ActionRanker,
    HeuristicRanker,
    LLMRanker,
    action_rank_json_schema,
)
from pentestai.orchestrator.world_model import WorldModel

SESSIONS: dict = {}


def _ep(name: str) -> Endpoint:
    return Endpoint(method="GET", path_template=f"/api/{name}/{{id}}", id_param="id")


def _oracle(name: str, *, oracle: str = "idor", rationale: str = "") -> RunOracle:
    return RunOracle(oracle=oracle, endpoint=_ep(name), victim_name="user_A",
                     attacker_name="user_B", rationale=rationale)


def _paths(actions) -> list[str]:
    return [a.endpoint.path_template for a in actions]


# --- HeuristicRanker ---


@pytest.mark.asyncio
async def test_heuristic_pivot_then_immunity_then_normal():
    pivot = _oracle("pivot", rationale="pivot: CONFIRMED cevaptaki 'profile' referansından türetildi")
    immunity = _oracle("immunity", rationale="immunity memory: bu örüntü daha önce kanıtlandı")
    normal = _oracle("normal", rationale="rutin")
    ranked = await HeuristicRanker().rank([normal, immunity, pivot], WorldModel(), SESSIONS)
    assert _paths(ranked) == ["/api/pivot/{id}", "/api/immunity/{id}", "/api/normal/{id}"]


@pytest.mark.asyncio
async def test_heuristic_tried_pivot_loses_to_untried_normal():
    world = WorldModel()
    pivot = _oracle("pivot", rationale="pivot: X")
    normal = _oracle("normal")
    world.record(pivot, Observation(action_type="run_oracle"))   # pivot artık denenmiş
    ranked = await HeuristicRanker().rank([pivot, normal], world, SESSIONS)
    # Tried cezası tüm bonuslardan büyük: denenmiş pivot, denenmemiş sıradan adayın önüne geçmez.
    assert _paths(ranked)[0] == "/api/normal/{id}"


@pytest.mark.asyncio
async def test_heuristic_auth_status_difference_prioritised():
    world = WorldModel()
    interesting = _ep("interesting")
    plain = _ep("plain")
    world.record(Probe(endpoint=interesting, actor_name="user_A"),
                 Observation(action_type="probe", status=200))
    world.record(Probe(endpoint=interesting, actor_name="user_B"),
                 Observation(action_type="probe", status=403))
    world.record(Probe(endpoint=plain, actor_name="user_A"),
                 Observation(action_type="probe", status=200))
    a = RunOracle(oracle="idor", endpoint=interesting, victim_name="user_A", attacker_name="user_B")
    b = RunOracle(oracle="idor", endpoint=plain, victim_name="user_A", attacker_name="user_B")
    ranked = await HeuristicRanker().rank([b, a], world, SESSIONS)
    assert _paths(ranked)[0] == "/api/interesting/{id}"


@pytest.mark.asyncio
async def test_heuristic_tiebreak_path_then_oracle():
    a = RunOracle(oracle="idor", endpoint=_ep("b"), victim_name="user_A", attacker_name="user_B")
    b = RunOracle(oracle="zzz", endpoint=_ep("a"), victim_name="user_A", attacker_name="user_B")
    c = RunOracle(oracle="idor", endpoint=_ep("a"), victim_name="user_A", attacker_name="user_B")
    ranked = await HeuristicRanker().rank([a, b, c], WorldModel(), SESSIONS)
    assert [(x.endpoint.path_template, x.oracle) for x in ranked] == [
        ("/api/a/{id}", "idor"), ("/api/a/{id}", "zzz"), ("/api/b/{id}", "idor")]


@pytest.mark.asyncio
async def test_heuristic_cheap_run_oracle_beats_enumeration_on_tie():
    ep = _ep("x")
    enum = EnumerateIds(endpoint=ep, actor_name="user_A", around_id="7", span=3)
    run = RunOracle(oracle="idor", endpoint=ep, victim_name="user_A", attacker_name="user_B")
    ranked = await HeuristicRanker().rank([enum, run], WorldModel(), SESSIONS)
    assert isinstance(ranked[0], RunOracle)


@pytest.mark.asyncio
async def test_heuristic_returns_same_pool_without_duplicates():
    candidates = [_oracle("a"), _oracle("b"), _oracle("c")]
    ranked = await HeuristicRanker().rank(candidates, WorldModel(), SESSIONS)
    assert len(ranked) == len(candidates)
    assert {id(a) for a in ranked} == {id(a) for a in candidates}


# --- LLMRanker ---


class _RankLLM(LLMClient):
    """Sıralama yanıtı veren / hata fırlatan sahte LLM (ağ yok)."""

    provider = "mock"
    model = "ranker"

    def __init__(self, completion: str = "", *, error: Exception | None = None):
        self.completion = completion
        self.error = error
        self.calls = 0
        self.fmt = None

    async def complete(self, system: str, user: str, *, fmt=None) -> str:
        self.calls += 1
        self.fmt = fmt
        if self.error is not None:
            raise self.error
        return self.completion


def _six() -> list[RunOracle]:
    return [_oracle(n) for n in ("a", "b", "c", "d", "e", "f")]


@pytest.mark.asyncio
async def test_llm_ranker_applies_permutation():
    llm = _RankLLM('{"ranking":[{"id":2,"score":9},{"id":0,"score":5},{"id":1,"score":1}]}')
    ranked = await LLMRanker(llm).rank(_six(), WorldModel(), SESSIONS)
    # İlk üçü LLM score sırası; kalanlar heuristik (path) sırayla sona eklenir.
    assert _paths(ranked) == [f"/api/{n}/{{id}}" for n in ("c", "a", "b", "d", "e", "f")]
    assert isinstance(llm.fmt, dict) and "ranking" in llm.fmt["properties"]


@pytest.mark.asyncio
async def test_llm_ranker_parses_embedded_array():
    llm = _RankLLM('Şöyle sıraladım: [{"id":3,"score":9},{"id":2,"score":2}]')
    ranked = await LLMRanker(llm).rank(_six(), WorldModel(), SESSIONS)
    assert _paths(ranked)[:2] == ["/api/d/{id}", "/api/c/{id}"]


@pytest.mark.asyncio
async def test_llm_ranker_drops_out_of_range_and_duplicate_indices():
    # 9 aralık dışı; ikinci 0 yinelenen → ikisi de düşer, havuza aksiyon eklenemez.
    llm = _RankLLM('{"ranking":[{"id":9,"score":99},{"id":0,"score":3},{"id":0,"score":1}]}')
    candidates = _six()
    ranked = await LLMRanker(llm).rank(candidates, WorldModel(), SESSIONS)
    assert len(ranked) == len(candidates)
    assert {id(a) for a in ranked} == {id(a) for a in candidates}
    assert _paths(ranked)[0] == "/api/a/{id}"


@pytest.mark.asyncio
async def test_llm_ranker_refusal_falls_back_and_notes():
    llm = _RankLLM(error=LLMRefusalError("içerik politikası"))
    ranker = LLMRanker(llm)
    ranked = await ranker.rank(_six(), WorldModel(), SESSIONS)
    assert _paths(ranked) == [f"/api/{n}/{{id}}" for n in ("a", "b", "c", "d", "e", "f")]
    assert len(ranker.refusal_notes) == 1
    note = ranker.refusal_notes[0]
    assert note.stage == "action_selection" and note.provider == "mock"
    assert "heuristik" in note.message


@pytest.mark.asyncio
async def test_llm_ranker_detects_refusal_text():
    llm = _RankLLM("I can't help with that.")
    ranker = LLMRanker(llm)
    await ranker.rank(_six(), WorldModel(), SESSIONS)
    assert len(ranker.refusal_notes) == 1


@pytest.mark.asyncio
async def test_llm_ranker_parse_error_falls_back_without_note():
    llm = _RankLLM("bu geçerli bir JSON değil")
    ranker = LLMRanker(llm)
    ranked = await ranker.rank(_six(), WorldModel(), SESSIONS)
    assert len(ranked) == 6
    assert ranker.refusal_notes == []       # parse hatası ≠ LLM reddi
    assert ranker.refusals == []


@pytest.mark.asyncio
async def test_llm_ranker_skips_llm_when_pool_fits_batch():
    llm = _RankLLM('{"ranking":[]}')
    ranked = await LLMRanker(llm, batch=4).rank(_six()[:4], WorldModel(), SESSIONS)
    assert len(ranked) == 4
    assert llm.calls == 0                   # anlamsız sıralama için token harcanmaz


@pytest.mark.asyncio
async def test_llm_ranker_empty_pool_returns_empty():
    llm = _RankLLM()
    assert await LLMRanker(llm).rank([], WorldModel(), SESSIONS) == []
    assert llm.calls == 0


def test_action_rank_schema_shape():
    schema = action_rank_json_schema()
    assert schema["properties"]["ranking"]["type"] == "array"
    item = schema["properties"]["ranking"]["items"]
    assert {"id", "score"} <= set(item["required"])


def test_rank_prompt_wraps_untrusted():
    system, user = PromptBuilder().build_action_rank("durum", "[0] run_oracle idor /api/x/{id}")
    assert "ranking" in system
    assert "<<UNTRUSTED_DATA>>" in user and "[0] run_oracle" in user


def test_action_ranker_is_abstract():
    with pytest.raises(TypeError):
        ActionRanker()   # abstract `rank` implement edilmeden örneklenemez


# --- AgenticOrchestrator bağlama ---


def test_agent_wires_ranker_by_llm_flag():
    det = AgenticOrchestrator(None, [], llm=None, batch=4)
    assert isinstance(det.ranker, HeuristicRanker)

    llm = MockLLMClient(completion="[]")
    with_llm = AgenticOrchestrator(None, [], llm=llm, batch=4)
    assert isinstance(with_llm.ranker, LLMRanker)
    # LLM selector havuzu ranker'ın anlamlı çalışacağı kadar büyük üretmeli (> batch).
    assert with_llm.selector.batch > with_llm.batch
