"""scripts.llm_compare — MockLLMClient ile ağsız ölçüm + tablo. LLMSelector red notu."""
import pytest

from pentestai.llm.client import MockLLMClient
from scripts.llm_compare import CORPUS, LlmComparer, build_client, main

VALID = ('[{"type":"idor","method":"GET","path_template":"/api/x/{id}","id_param":"id",'
         '"id_location":"path","resource_key":"x","rationale":"r"}]')


async def test_compare_counts_and_table():
    targets = [("iyi", MockLLMClient(completion=VALID)),
               ("retci", MockLLMClient(completion="I can't help with that.")),
               ("bos", MockLLMClient(completion="[]"))]
    stats = await LlmComparer().run(targets)
    n = len(CORPUS)
    iyi, retci, bos = stats
    assert (iyi.answered, iyi.refused, iyi.valid_hypotheses) == (n, 0, n)
    assert (retci.answered, retci.refused, retci.refusal_rate) == (0, n, 1.0)
    assert (bos.answered, bos.refused, bos.valid_hypotheses) == (n, 0, 0)
    md = LlmComparer.render_markdown(stats)
    assert "| retci |" in md and "100%" in md


def test_build_client_model_tag_with_colon():
    label, client = build_client("ollama:qwen3.8:27b")
    assert label == "ollama:qwen3.8:27b" and client.model == "qwen3.8:27b"
    with pytest.raises(ValueError):
        build_client("bilinmeyen:x")


def test_main_mock_writes_markdown(tmp_path, capsys):
    out = tmp_path / "t.md"
    assert main(["--target", "mock", "--out", str(out)]) == 0
    assert "| mock |" in out.read_text(encoding="utf-8")


async def test_llm_selector_records_refusal():
    from pentestai.orchestrator.selectors import LLMSelector
    from pentestai.orchestrator.world_model import WorldModel

    sel = LLMSelector(MockLLMClient(completion="Üzgünüm, yardımcı olamam."))
    assert await sel.next_actions(WorldModel(), [], {}) == []
    assert len(sel.refusals) == 1
    ok = LLMSelector(MockLLMClient(completion="[]"))
    await ok.next_actions(WorldModel(), [], {})
    assert ok.refusals == []
