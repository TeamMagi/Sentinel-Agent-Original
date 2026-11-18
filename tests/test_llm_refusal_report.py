"""LLM redlerinin tarama çıktısına/rapora taşınması — kapsam uyarısı, bulgu DEĞİL."""
import json

import httpx
import pytest

from pentestai.llm.client import MockLLMClient
from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.models.llm_refusal import LlmRefusalNote
from pentestai.net import SessionStore
from pentestai.report.llm_refusal import cli_line
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
ENDPOINTS = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]
ORDERS = {
    "A-100": {"id": "A-100", "owner": "user_A", "email": "alice@test.local"},
    "B-200": {"id": "B-200", "owner": "user_B", "email": "bob@test.local"},
}
REFUSAL = "Üzgünüm, bu konuda yardımcı olamam."


def handler(request):
    oid = request.url.path.rsplit("/", 1)[-1]
    return httpx.Response(200, json=ORDERS[oid]) if oid in ORDERS else httpx.Response(404, json={})


async def _run(tmp_path, completion: str):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000), out_dir=str(tmp_path),
                      llm=MockLLMClient(completion=completion))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"orders": "A-100"}))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"}),
                           own_object_ids={"orders": "B-200"}))
    hyps = await scanner.planner.generate(ENDPOINTS)
    findings = await scanner.run_hypotheses([A, B], hyps)
    _, root = scanner.save(findings, "active", sessions=[A, B])
    await scanner.aclose()
    return scanner, findings, root


@pytest.mark.asyncio
async def test_refusal_reaches_result_and_reports(tmp_path):
    scanner, findings, root = await _run(tmp_path / "r", REFUSAL)
    notes = scanner.llm_refusals()
    assert notes and notes[0].stage == "hypothesis" and len(notes[0].message) <= 300
    md = (root / "report.md").read_text(encoding="utf-8")
    assert "Kapsam uyarıları" in md and "hipotez üretmeyi 1 kez reddetti" in md
    assert "Kapsam uyarıları" in (root / "report.html").read_text(encoding="utf-8")
    meta = json.loads((root / "run_meta.json").read_text(encoding="utf-8"))
    assert meta["llm_refusals"][0]["stage"] == "hypothesis" and meta["coverage_warnings"]
    assert isinstance(json.loads((root / "findings.json").read_text(encoding="utf-8")), list)
    assert cli_line(notes).startswith("[uyarı]")
    # red zafiyet değildir: SARIF'e ek sonuç düşmez
    sarif = json.loads((root / "report.sarif").read_text(encoding="utf-8"))
    _, _, root_ok = await _run(tmp_path / "ok", "[]")
    sarif_ok = json.loads((root_ok / "report.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == len(sarif_ok["runs"][0]["results"])


@pytest.mark.asyncio
async def test_no_refusal_no_section_and_findings_unchanged(tmp_path):
    _, f_ok, root_ok = await _run(tmp_path / "ok", "[]")
    scanner, f_ref, _ = await _run(tmp_path / "ref", REFUSAL)
    assert scanner.llm_refusals()
    assert "Kapsam uyarıları" not in (root_ok / "report.md").read_text(encoding="utf-8")
    assert "Kapsam uyarıları" not in (root_ok / "report.html").read_text(encoding="utf-8")
    assert not (root_ok / "run_meta.json").exists()
    assert cli_line([]) == ""
    assert [(f.type, f.verdict) for f in f_ok] == [(f.type, f.verdict) for f in f_ref]


def test_note_message_capped_and_selector_note_aggregates():
    n = LlmRefusalNote(provider="x", stage="action_selection", message="a" * 900, reason="b" * 900)
    assert len(n.message) == 300 and len(n.reason) == 300
    assert "aksiyon seçmeyi 2 kez" in cli_line([n, n])
