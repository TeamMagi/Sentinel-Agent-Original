"""Faz 5 / T5 — envanter rapor bloğu, HTML kaçışı ve artefaktı (ağsız).

Hiçbir test gerçek hedefe istek atmaz; Scanner.save yolu yalnızca yerel dosya yazar.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from pentestai.inventory.diff import DiffResult, summarize
from pentestai.inventory.models import (
    ChangeCategory,
    EndpointObservation,
    InventoryChange,
    InventoryRecord,
)
from pentestai.inventory.store import InventoryStore
from pentestai.inventory.tracker import InventoryTracker
from pentestai.models import BudgetConfig, Endpoint, Scope
from pentestai.report.inventory_section import InventoryReportSection
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
Section = InventoryReportSection


def _change(
    category: ChangeCategory, key: str, detail: str, priority: int = 100,
) -> InventoryChange:
    return InventoryChange(category=category, key=key, detail=detail, priority=priority)


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])


def _result() -> DiffResult:
    observations = [
        EndpointObservation(method="GET", path_template="/api/a", sources=["config"]),
        EndpointObservation(method="GET", path_template="/api/b", sources=["config"]),
    ]
    records = {obs.key: InventoryRecord.from_observation(obs, NOW) for obs in observations}
    changes = [_change(ChangeCategory.NEW, "GET /api/b", "yeni uç nokta GET /api/b", priority=0)]
    return DiffResult(changes=changes, records=records, first_run=False)


def _scanner(tmp_path, planned: set[str] | None) -> tuple[Scanner, InventoryTracker]:
    tracker = InventoryTracker(InventoryStore(str(tmp_path / "inventory.sqlite")), BASE)
    tracker.result = _result()
    tracker.planned_keys = planned
    scanner = Scanner(
        BASE, _scope(), BudgetConfig(max_rps_per_host=1000),
        out_dir=str(tmp_path / "runs"), inventory=tracker,
    )
    endpoints = [
        Endpoint(method="GET", path_template="/api/a"),
        Endpoint(method="GET", path_template="/api/b"),
    ]
    scanner.register_surface(endpoints, "config")
    scanner._record_tested(endpoints[0], "idor")   # /api/b plana girip test edilmemiş kalsın
    return scanner, tracker


def test_first_run_text():
    md = Section.render_markdown(
        DiffResult(first_run=True), endpoints_total=7, tested=5,
        untested=["GET /api/b"], first_run=True,
    )
    assert md.startswith("## Envanter (bu koşum)\n")
    assert "İlk envanter koşumu: 7 uç kayda alındı (karşılaştırma bir sonraki koşumda)" in md
    assert "Test edilemeyenler: GET /api/b" in md
    assert "Bu koşum:" not in md


def test_changed_text_counts_emojis_warning_and_stale_collapse():
    changes = [
        _change(ChangeCategory.MISSING, "GET /api/old", "2. taramadır görülmedi", priority=5),
        _change(
            ChangeCategory.NEW, "POST /api/v2/coupons/transfer", "yeni uç nokta", priority=0),
        _change(
            ChangeCategory.AUTH_CHANGED, "GET /api/reports/{id}",
            "anonymous: 401 → 200 — dün kimlik istiyordu, bugün açık (UYARI, kanıt değil)",
            priority=1,
        ),
        _change(ChangeCategory.SHAPE_CHANGED, "GET /api/users", "yanıt şekli değişti", priority=3),
        _change(ChangeCategory.CHANGED, "GET /api/orders", "parametreler değişti", priority=2),
        _change(ChangeCategory.STALE, "GET /api/slow", "15 gündür test edilmedi — bayat",
                priority=6),
    ]
    md = Section.render_markdown(
        DiffResult(changes=changes), endpoints_total=142, tested=139,
        untested=["PUT /api/settings", "GET /api/x"], first_run=False,
    )
    assert "Bu koşum: 142 uç (1 yeni, 3 değişti, 1 kayboldu) · 139 test edildi · " \
           "2 test edilemedi" in md
    order = [md.index(emoji) for emoji in ("🆕", "🔓", "✏️", "🧬", "❌", "⏳")]
    assert order == sorted(order)
    assert "🆕 POST /api/v2/coupons/transfer — yeni uç nokta" in md
    assert "anonymous: 401 → 200 — dün kimlik istiyordu, bugün açık (UYARI, kanıt değil)" in md
    assert "⏳ 1 uç bayat (≥14 gün test edilmedi)" in md
    assert "15 gündür test edilmedi — bayat" not in md   # STALE tek satıra indirgendi
    assert "Test edilemeyenler: PUT /api/settings, GET /api/x" in md


def test_every_auth_change_line_carries_warning():
    change = _change(ChangeCategory.AUTH_CHANGED, "GET /api/a",
                     "user: 200 → 401 — erişim kapandı", priority=4)
    md = Section.render_markdown(
        DiffResult(changes=[change]), endpoints_total=1, tested=1,
        untested=[], first_run=False,
    )
    assert "user: 200 → 401 — erişim kapandı (UYARI, kanıt değil)" in md
    assert "CONFIRMED" not in md


def test_limits_30_changes_and_10_untested():
    changes = [
        _change(ChangeCategory.NEW, f"GET /e{i:02d}", "yeni uç nokta", priority=0)
        for i in range(31)
    ]
    untested = [f"GET /u{i:02d}" for i in range(12)]
    md = Section.render_markdown(
        DiffResult(changes=changes), endpoints_total=31, tested=0,
        untested=untested, first_run=False,
    )
    assert md.count("🆕") == 30
    assert "... ve 1 değişiklik daha" in md
    assert "GET /e30" not in md
    assert "Test edilemeyenler: GET /u00, GET /u01, GET /u02, GET /u03, GET /u04, " \
           "GET /u05, GET /u06, GET /u07, GET /u08, GET /u09 ... ve 2 uç daha" in md
    assert "GET /u10" not in md


def test_clean_scan_still_produces_block():
    md = Section.render_markdown(
        DiffResult(), endpoints_total=2, tested=2, untested=[], first_run=False,
    )
    assert md.startswith("## Envanter (bu koşum)\n")
    assert "Bu koşum: 2 uç (0 yeni, 0 değişti, 0 kayboldu) · 2 test edildi" in md
    assert "Değişiklik yok — dünkü envanterle aynı." in md
    assert "test edilemedi" not in md


def test_profile_truncation_never_claims_clean_inventory():
    md = Section.render_markdown(
        DiffResult(), endpoints_total=5, tested=3, untested=[], first_run=False,
        profile_truncated=True, unprofiled=2,
    )
    assert "⚠️ Profil bütçesi doldu: 2 uç profillenmedi — bu uçlarda yetki/şekil " \
           "değişikliği bilinmiyor" in md
    assert "Değişiklik yok — dünkü envanterle aynı." not in md
    assert "Profillenen uçlarda değişiklik yok." in md

    payload = Section.to_json(
        DiffResult(), endpoints_total=5, tested=3, untested=[], first_run=False,
        profile_truncated=True, unprofiled=2,
    )
    assert payload["profile_truncated"] is True
    assert payload["unprofiled"] == 2


def test_html_is_escaped():
    change = _change(
        ChangeCategory.NEW, "GET /api/<script>alert(1)</script>", "yeni <img src=x> uç",
        priority=0,
    )
    out = Section.render_html(
        DiffResult(changes=[change]), endpoints_total=1, tested=0,
        untested=["GET /api/<script>"], first_run=False,
    )
    assert out.startswith("<section>\n<h2>Envanter (bu koşum)</h2>")
    assert "<script>" not in out and "<img" not in out
    assert "&lt;script&gt;" in out and "&lt;img" in out
    assert "UYARI, kanıt değil" not in out   # bu satır yetki değişimi değil


def test_to_json_schema():
    changes = [
        _change(ChangeCategory.NEW, "GET /a", "yeni uç nokta", priority=0),
        _change(ChangeCategory.STALE, "GET /b", "bayat", priority=6),
    ]
    payload = Section.to_json(
        DiffResult(changes=changes), endpoints_total=2, tested=1,
        untested=["GET /b"], first_run=False,
    )
    assert set(payload) == {
        "first_run", "summary", "endpoints_total", "tested", "untested",
        "profile_truncated", "unprofiled", "changes",
    }
    assert payload["profile_truncated"] is False and payload["unprofiled"] == 0
    assert payload["summary"] == summarize(changes)
    assert payload["changes"][0]["category"] == "new"
    assert payload["untested"] == ["GET /b"] and payload["tested"] == 1
    assert json.loads(json.dumps(payload))["endpoints_total"] == 2


def test_scanner_save_writes_block_at_top_and_inventory_diff_json(tmp_path):
    scanner, _tracker = _scanner(tmp_path / "r1", {"GET /api/a", "GET /api/b"})
    _run_id, root = scanner.save([], "active")
    md = (root / "report.md").read_text(encoding="utf-8")
    assert md.startswith("## Envanter (bu koşum)\n")
    assert "Bu koşum: 2 uç (1 yeni, 0 değişti, 0 kayboldu) · 1 test edildi · " \
           "1 test edilemedi" in md
    assert md.index("## Envanter (bu koşum)") < md.index("# Sentinel-Agent")
    html = (root / "report.html").read_text(encoding="utf-8")
    assert "<section>" in html and html.index("<body>") < html.index("<section>")
    data = json.loads((root / "inventory_diff.json").read_text(encoding="utf-8"))
    assert data["endpoints_total"] == 2 and data["tested"] == 1
    assert data["untested"] == ["GET /api/b"]
    assert data["summary"]["new"] == 1 and data["changes"][0]["key"] == "GET /api/b"
    assert data["first_run"] is False
    assert len(json.loads((root / "surface.json").read_text(encoding="utf-8"))) == 2


def test_scanner_save_excludes_out_of_plan_endpoints_from_untested(tmp_path):
    scanner, _tracker = _scanner(tmp_path / "r2", {"GET /api/a"})
    _run_id, root = scanner.save([], "active")
    data = json.loads((root / "inventory_diff.json").read_text(encoding="utf-8"))
    assert data["untested"] == []   # /api/b delta planı dışında → "test edilemedi" değil
    assert "Test edilemeyenler:" not in (root / "report.md").read_text(encoding="utf-8")

    empty_plan, _ = _scanner(tmp_path / "r4", set())   # delta'da değişiklik yok → plan boş
    _run_id, root_empty = empty_plan.save([], "active")
    data_empty = json.loads((root_empty / "inventory_diff.json").read_text(encoding="utf-8"))
    assert data_empty["untested"] == []

    unplanned, _ = _scanner(tmp_path / "r5", None)   # plan() çağrılmadı → filtre yok
    _run_id, root_unplanned = unplanned.save([], "active")
    data_unplanned = json.loads(
        (root_unplanned / "inventory_diff.json").read_text(encoding="utf-8"))
    assert data_unplanned["untested"] == ["GET /api/b"]


def test_partial_warning_stays_above_inventory_block(tmp_path):
    scanner, _tracker = _scanner(tmp_path / "r3", {"GET /api/a", "GET /api/b"})
    scanner.partial = True
    scanner.stop_reason = "bütçe doldu"
    _run_id, root = scanner.save([], "active")
    md = (root / "report.md").read_text(encoding="utf-8")
    assert md.startswith("> UYARI: bütçe doldu — sonuçlar kısmi.")
    assert md.index("> UYARI") < md.index("## Envanter") < md.index("# Sentinel-Agent")


def test_scanner_save_surfaces_profile_truncation_in_block_and_json(tmp_path):
    scanner, tracker = _scanner(tmp_path / "r6", {"GET /api/a", "GET /api/b"})
    tracker.profile_truncated = True
    tracker.unprofiled_keys = {"GET /api/b"}
    _run_id, root = scanner.save([], "active")

    md = (root / "report.md").read_text(encoding="utf-8")
    assert "⚠️ Profil bütçesi doldu: 1 uç profillenmedi" in md
    assert "Değişiklik yok — dünkü envanterle aynı." not in md
    data = json.loads((root / "inventory_diff.json").read_text(encoding="utf-8"))
    assert data["profile_truncated"] is True and data["unprofiled"] == 1
