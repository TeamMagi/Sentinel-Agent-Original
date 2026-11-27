"""Faz 5 / T6 — envanter + farkın uçtan uca, ağsız çıkış kriteri.

Gerçek ``Scanner`` + ``InventoryTracker`` + ``InventoryStore(tmp_path/\"inv.sqlite\")``
kullanılır; tek ağ yüzeyi durumlu bir ``httpx.MockTransport``'dur. İki koşum arasında sahte
hedefin durumu değiştirilir: uç eklenir/kaldırılır, anon erişim açılır, yanıt şekline hassas
alan eklenir. Gerçek senaryoda yeni uçları keşif (OpenAPI/HAR/crawl) bulur; testin kararlı
olması için ``endpoints`` listesi doğrudan ``run_recon_scan``'e verilir.

Planlayıcı, bu dosyada yalnızca tek bir deterministik hipotezle (BOPLA) sınırlanır: amaç
envanter farkını doğrulamak, oracle'ların tüm zafiyet ailelerini yeniden taramak değildir.
Verdict yine gerçek oracle'dan gelir; bu modül CONFIRMED üretmez.
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx
import pytest

from pentestai.inventory.models import ChangeCategory
from pentestai.inventory.store import InventoryStore
from pentestai.inventory.tracker import InventoryTracker
from pentestai.models import (
    Actor,
    AuthState,
    BudgetConfig,
    Endpoint,
    Finding,
    Hypothesis,
    Scope,
)
from pentestai.net import Session, SessionStore
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
FIRST = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
VICTIM_EMAIL = "kurban@example.com"
API_TOKEN = "SECRET-TOKEN-A"

# Somut istek yolu → şablon yol; durum değişiklikleri şablon anahtarıyla yapılır.
_ROUTES = {
    "/api/orders": "/api/orders",
    "/api/reports/101": "/api/reports/{id}",
    "/api/reports/202": "/api/reports/{id}",
    "/api/profile": "/api/profile",
    "/api/legacy": "/api/legacy",
    "/api/v2/coupons": "/api/v2/coupons",
}


class FakeTarget:
    """İki koşum arasında mutate edilebilen durumlu sahte hedef (asla gerçek ağ yok)."""

    def __init__(self) -> None:
        self.present: set[str] = {
            "/api/orders", "/api/reports/{id}", "/api/profile", "/api/legacy",
        }
        self.anon_reports_open = False
        self.profile_ssn = False
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Duruma göre yanıt üretir; istekleri yalnızca test bellek listesine kaydeder."""
        self.requests.append(request)
        path = request.url.path
        template = _ROUTES.get(path)
        token = request.headers.get("authorization", "")
        actor = "user_A" if token == "Bearer A" else "user_B" if token == "Bearer B" else "anon"
        if template is None or template not in self.present:
            return httpx.Response(404, json={"error": "not found"})
        if template == "/api/reports/{id}":
            if actor == "anon" and not self.anon_reports_open:
                return httpx.Response(401, json={"error": "unauthorized"})
            return httpx.Response(200, json={"id": path.rsplit("/", 1)[-1], "title": "quarterly"})
        if template == "/api/profile":
            body: dict[str, object] = {"id": actor, "email": VICTIM_EMAIL, "plan": "free"}
            if self.profile_ssn:
                body["ssn"] = ""   # alan ADI şekle girer; PII DEĞERİ hiçbir yere yazılmaz
            return httpx.Response(200, json=body)
        if template == "/api/orders":
            return httpx.Response(200, json={"id": actor, "total": 10})
        if template == "/api/v2/coupons":
            return httpx.Response(200, json={"code": "SAVE10"})
        return httpx.Response(200, json={"legacy": True})


@dataclass
class RunContext:
    """Bir senaryonun tüm bağımlılıkları ve koşum sürücüsü (DI, global durum yok)."""

    target: FakeTarget
    inventory: InventoryStore
    tracker: InventoryTracker
    scanner: Scanner
    net_store: SessionStore
    sessions: list[Session]
    anon: Session
    endpoints: list[Endpoint]
    moment: list[datetime]

    @property
    def inventory_path(self) -> Path:
        return self.inventory.path

    def advance(self, days: int = 1) -> None:
        """Enjekte edilen saati ilerletir (STALE gürültüsü olmadan koşumlar arası ayırım)."""
        self.moment[0] += timedelta(days=days)

    async def scan(
        self, endpoints: Optional[list[Endpoint]] = None,
    ) -> tuple[list[Finding], Path]:
        """Gerçek Scanner koşumu + tracker.finish + yerel rapor kaydı."""
        selected = self.endpoints if endpoints is None else endpoints
        self.scanner.surface_sources.clear()
        self.scanner.surface_tested.clear()
        for endpoint in selected:
            # Gerçek akışta bu kayıt CLI/config keşfi tarafından yapılır (yaml → register_surface).
            self.scanner.register_surface([endpoint], "config")
        findings = await self.scanner.run_recon_scan(
            self.sessions, selected, bootstrap=False, exposure_scan=False,
            info_leak_scan=False, rate_limit_scan=False, cve_scan=False,
            tls_scan=False, template_scan=False,
        )
        self.tracker.finish(self.scanner.surface_tested, findings)
        _run_id, root = self.scanner.save(findings, "active")
        assert self.scanner.partial is False   # bütçe/süre çıkış kriterini bozmamalı
        return findings, root

    async def aclose(self) -> None:
        await self.net_store.aclose_all()
        self.inventory.close()


def _build(tmp_path: Path) -> RunContext:
    target = FakeTarget()
    scope = Scope(
        allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
        # Profilin yazma methodu ATLADIğını kanıtlayabilmek için policy onları engellemez.
        allowed_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
    )
    moment = [FIRST]
    inventory = InventoryStore(tmp_path / "inv.sqlite")
    tracker = InventoryTracker(
        inventory, BASE, mode="delta", clock=lambda: moment[0], profile_max_requests=100)

    async def limited_planner(endpoints: list[Endpoint]) -> list[Hypothesis]:
        return [
            Hypothesis(type="excessive_data_exposure", endpoint=endpoint,
                       rationale="envanter çıkış kriteri: gerçek BOPLA oracle'ı ile tek test")
            for endpoint in endpoints
        ]

    scanner = Scanner(
        BASE, scope, BudgetConfig(max_total_requests=2000, max_rps_per_host=1000,
                                  max_wall_clock_sec=120),
        out_dir=str(tmp_path / "runs"), inventory=tracker,
    )
    scanner.planner.generate = limited_planner

    net_store = SessionStore(base_url=BASE, transport=httpx.MockTransport(target.handler))
    actor_a = net_store.create(Actor(
        name="user_A", role="user",
        auth=AuthState(headers={"Authorization": "Bearer A", "X-Api-Key": API_TOKEN}),
        own_object_ids={"reports": "101"},
    ))
    actor_b = net_store.create(Actor(
        name="user_B", role="user",
        auth=AuthState(headers={"Authorization": "Bearer B"}),
        own_object_ids={"reports": "202"},
    ))
    anon = net_store.create(Actor(name="anonymous", role="anonymous"))
    scanner.anon = anon   # build_sessions() çağrılmaz; hiç DNS/PinnedTransport gerekmez

    endpoints = [
        Endpoint(method="GET", path_template="/api/orders"),
        Endpoint(method="GET", path_template="/api/reports/{id}", id_param="id"),
        Endpoint(method="GET", path_template="/api/profile"),
        Endpoint(method="GET", path_template="/api/legacy"),
    ]
    return RunContext(
        target=target, inventory=inventory, tracker=tracker, scanner=scanner,
        net_store=net_store, sessions=[actor_a, actor_b], anon=anon,
        endpoints=endpoints, moment=moment,
    )


@asynccontextmanager
async def _open(tmp_path: Path) -> AsyncIterator[RunContext]:
    ctx = _build(tmp_path)
    try:
        yield ctx
    finally:
        await ctx.aclose()


def _coupon() -> Endpoint:
    return Endpoint(method="GET", path_template="/api/v2/coupons")


# --- (a) ilk koşum ------------------------------------------------------------
@pytest.mark.asyncio
async def test_first_run_creates_baseline_without_changes(tmp_path: Path):
    async with _open(tmp_path) as ctx:
        _findings, root = await ctx.scan()

        assert ctx.tracker.result is not None
        assert ctx.tracker.result.first_run is True
        assert ctx.tracker.result.changes == []
        assert ctx.tracker.planned_keys == {
            "GET /api/orders", "GET /api/reports/{id}", "GET /api/profile", "GET /api/legacy",
        }
        assert set(ctx.inventory.load(BASE)) == ctx.tracker.planned_keys
        report = (root / "report.md").read_text(encoding="utf-8")
        assert "İlk envanter koşumu: 4 uç kayda alındı (karşılaştırma bir sonraki koşumda)" in report
        data = json.loads((root / "inventory_diff.json").read_text(encoding="utf-8"))
        assert data["first_run"] is True and data["summary"] == {} and data["tested"] == 4


# --- (b) yeni uç → NEW + delta'da gerçekten test ------------------------------
@pytest.mark.asyncio
async def test_new_endpoint_is_reported_and_tested_in_delta(tmp_path: Path):
    async with _open(tmp_path) as ctx:
        await ctx.scan()
        ctx.advance()
        ctx.target.present.add("/api/v2/coupons")
        findings, root = await ctx.scan(ctx.endpoints + [_coupon()])

        assert ctx.tracker.result is not None
        changes = ctx.tracker.result.changes
        assert [c.category for c in changes] == [ChangeCategory.NEW]
        assert changes[0].key == "GET /api/v2/coupons" and changes[0].priority == 0
        assert ctx.tracker.planned_keys == {"GET /api/v2/coupons"}
        assert any(f.endpoint == "/api/v2/coupons" for f in findings)
        surface = json.loads((root / "surface.json").read_text(encoding="utf-8"))
        coupon_entry = next(e for e in surface if e["path_template"] == "/api/v2/coupons")
        assert coupon_entry["tested"] is True
        record = ctx.inventory.load(BASE)["GET /api/v2/coupons"]
        assert record.last_tested == ctx.moment[0]
        assert "🆕 GET /api/v2/coupons" in (root / "report.md").read_text(encoding="utf-8")


# --- (c) anon'a açılan uç → AUTH_CHANGED, UYARI, kanıt değil ------------------
@pytest.mark.asyncio
async def test_auth_change_is_warning_only_and_creates_no_confirmed(tmp_path: Path):
    async with _open(tmp_path) as ctx:
        await ctx.scan()
        ctx.advance()
        ctx.target.anon_reports_open = True
        findings, root = await ctx.scan()

        assert ctx.tracker.result is not None
        changes = ctx.tracker.result.changes
        assert [c.category for c in changes] == [ChangeCategory.AUTH_CHANGED]
        change = changes[0]
        assert change.key == "GET /api/reports/{id}" and change.priority == 1
        assert change.before == {"role": "anonymous", "status": 401}
        assert change.after == {"role": "anonymous", "status": 200}
        report = (root / "report.md").read_text(encoding="utf-8")
        assert "anonymous: 401 → 200" in report and "UYARI, kanıt değil" in report
        assert all(f.verdict != "CONFIRMED" for f in findings)   # tek başına kanıt DEĞİL
        data = json.loads((root / "inventory_diff.json").read_text(encoding="utf-8"))
        assert data["summary"] == {"auth_changed": 1}


# --- (d) hassas alan eklenmesi → SHAPE_CHANGED --------------------------------
@pytest.mark.asyncio
async def test_sensitive_field_added_is_shape_changed(tmp_path: Path):
    async with _open(tmp_path) as ctx:
        await ctx.scan()
        ctx.advance()
        ctx.target.profile_ssn = True
        _findings, root = await ctx.scan()

        assert ctx.tracker.result is not None
        changes = ctx.tracker.result.changes
        assert [c.category for c in changes] == [ChangeCategory.SHAPE_CHANGED]
        change = changes[0]
        assert change.key == "GET /api/profile" and change.priority == 1
        assert "hassas alan eklendi: ssn" in change.detail
        assert "ssn" in str(change.after) and VICTIM_EMAIL not in str(change.after)
        report = (root / "report.md").read_text(encoding="utf-8")
        assert "🧬 GET /api/profile" in report and "hassas alan eklendi" in report


# --- (d2) parametre adı değişimi → CHANGED ------------------------------------
@pytest.mark.asyncio
async def test_renamed_id_param_is_changed(tmp_path: Path):
    async with _open(tmp_path) as ctx:
        await ctx.scan()
        ctx.advance()
        renamed = [
            Endpoint(method=ep.method, path_template=ep.path_template, id_param="uid")
            if ep.path_template == "/api/reports/{id}" else ep
            for ep in ctx.endpoints
        ]
        _findings, root = await ctx.scan(renamed)

        assert ctx.tracker.result is not None
        changes = ctx.tracker.result.changes
        assert [c.category for c in changes] == [ChangeCategory.CHANGED]
        assert changes[0].key == "GET /api/reports/{id}"
        assert changes[0].detail == "parametreler değişti — eklenen: uid; çıkan: id"
        data = json.loads((root / "inventory_diff.json").read_text(encoding="utf-8"))
        assert data["summary"] == {"changed": 1}


# --- (d3) 14 gündür test edilmeyen uçlar → STALE -------------------------------
@pytest.mark.asyncio
async def test_untouched_endpoints_become_stale(tmp_path: Path):
    async with _open(tmp_path) as ctx:
        await ctx.scan()
        ctx.advance(15)
        _findings, root = await ctx.scan()

        assert ctx.tracker.result is not None
        changes = ctx.tracker.result.changes
        assert len(changes) == 4
        assert all(c.category is ChangeCategory.STALE for c in changes)
        data = json.loads((root / "inventory_diff.json").read_text(encoding="utf-8"))
        assert data["summary"] == {"stale": 4}
        report = (root / "report.md").read_text(encoding="utf-8")
        assert "⏳ 4 uç bayat (≥14 gün test edilmedi)" in report


# --- (e) kaybolan uç: 3. taramada emekli, sonraki koşumda RETURNED -------------
@pytest.mark.asyncio
async def test_missing_retires_after_three_scans_then_returns(tmp_path: Path):
    async with _open(tmp_path) as ctx:
        without_legacy = ctx.endpoints[:3]
        await ctx.scan()
        expected = [
            "1. taramadır görülmedi",
            "2. taramadır görülmedi",
            "3. taramadır görülmedi — kaldırıldı sayıldı",
        ]
        for day, detail in enumerate(expected, start=2):
            ctx.advance()
            _findings, root = await ctx.scan(without_legacy)
            changes = ctx.tracker.result.changes if ctx.tracker.result else []
            assert [c.category for c in changes] == [ChangeCategory.MISSING]
            assert changes[0].key == "GET /api/legacy" and changes[0].detail == detail
            record = ctx.inventory.load(BASE)["GET /api/legacy"]
            assert record.missing_streak == day - 1 and record.removed is (day == 4)
            data = json.loads((root / "inventory_diff.json").read_text(encoding="utf-8"))
            assert data["summary"] == {"missing": 1}

        ctx.advance()
        _findings, root = await ctx.scan()   # uç geri geldi
        changes = ctx.tracker.result.changes if ctx.tracker.result else []
        assert [c.category for c in changes] == [ChangeCategory.RETURNED]
        assert changes[0].key == "GET /api/legacy"
        assert "yeniden görüldü — 3 taramadır yoktu" in changes[0].detail
        record = ctx.inventory.load(BASE)["GET /api/legacy"]
        assert record.missing_streak == 0 and record.removed is False
        assert "🔁 GET /api/legacy" in (root / "report.md").read_text(encoding="utf-8")


# --- (f) artefakt sayıları + sqlite'da ham değer yok --------------------------
@pytest.mark.asyncio
async def test_artifact_counts_and_sqlite_has_no_raw_values(tmp_path: Path):
    async with _open(tmp_path) as ctx:
        await ctx.scan()
        ctx.advance()
        ctx.target.present.add("/api/v2/coupons")
        ctx.target.present.discard("/api/legacy")
        ctx.target.anon_reports_open = True
        ctx.target.profile_ssn = True
        _findings, root = await ctx.scan(ctx.endpoints[:3] + [_coupon()])

        data = json.loads((root / "inventory_diff.json").read_text(encoding="utf-8"))
        assert data["summary"] == {
            "auth_changed": 1, "missing": 1, "new": 1, "shape_changed": 1,
        }
        assert data["endpoints_total"] == 4 and data["tested"] == 3 and data["untested"] == []
        keys = {(c["category"], c["key"]) for c in data["changes"]}
        assert keys == {
            ("new", "GET /api/v2/coupons"),
            ("auth_changed", "GET /api/reports/{id}"),
            ("shape_changed", "GET /api/profile"),
            ("missing", "GET /api/legacy"),
        }
        report = (root / "report.md").read_text(encoding="utf-8")
        assert "Bu koşum: 4 uç (1 yeni, 2 değişti, 1 kayboldu) · 3 test edildi" in report
        assert "UYARI, kanıt değil" in report and "1. taramadır görülmedi" in report

        raw = ctx.inventory_path.read_bytes()
        for secret in (VICTIM_EMAIL, "Bearer A", API_TOKEN, "123-45-6789"):
            assert secret.encode("utf-8") not in raw


# --- (g) profil aşaması yalnız GET ---------------------------------------------
@pytest.mark.asyncio
async def test_profile_phase_sends_only_get_requests(tmp_path: Path):
    async with _open(tmp_path) as ctx:
        writes = [
            Endpoint(method="POST", path_template="/api/orders"),
            Endpoint(method="PUT", path_template="/api/orders/{id}", id_param="id"),
            Endpoint(method="DELETE", path_template="/api/orders/{id}", id_param="id"),
        ]
        before = len(ctx.target.requests)
        result = await ctx.tracker.observe(
            ctx.scanner.replayer, ctx.endpoints + writes, ctx.sessions, ctx.anon,
            sources={("get", "/api/orders"): ["config"]},
        )
        sent = ctx.target.requests[before:]

        assert len(sent) == len(ctx.endpoints) * 3   # 2 aktör + anon, uç başına birer GET
        assert {request.method for request in sent} == {"GET"}
        assert not any(request.method in {"POST", "PUT", "PATCH", "DELETE"} for request in sent)
        assert result.records["GET /api/orders"].sources == ["config"]
        assert all(result.records[f"{w.method} {w.path_template}"].auth_profile == {}
                   for w in writes)
        assert all(result.records[f"{w.method} {w.path_template}"].response_shape is None
                   for w in writes)
