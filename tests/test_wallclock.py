"""Süre bütçesi (max_wall_clock_sec) gerçekten uygulanır: Retry-After üst sınırı, takılan istek,
toplam tarama deadline'ı. Network yok (httpx.MockTransport); gerçek süre beklenmez (saniyeler)."""
import asyncio
import time

import httpx
import pytest

from pentestai.models import (
    Actor,
    AuthState,
    BudgetConfig,
    CapturedRequest,
    Endpoint,
    Hypothesis,
    Scope,
)
from pentestai.net import BudgetTracker, RateLimiter, Replayer, SessionStore
from pentestai.net.limits import BudgetExceeded, RetryPolicy
from pentestai.policy import PolicyEngine
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
SCOPE = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_methods=["GET", "HEAD"])


def _replayer(handler, *, wall: int = 900, retry: RetryPolicy | None = None):
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    sess = store.create(Actor(name="a", role="user", auth=AuthState(headers={"Authorization": "Bearer A"})))
    rp = Replayer(PolicyEngine(SCOPE), budget=BudgetTracker(1000, wall),
                  limiter=RateLimiter(1000), retry=retry)
    return rp, sess, store


def _req() -> CapturedRequest:
    return CapturedRequest(method="GET", url=f"{BASE}/api/x")


def test_seconds_left_clamps_to_zero():
    b = BudgetTracker(10, 0)
    time.sleep(0.01)
    assert b.seconds_left == 0.0
    assert BudgetTracker(10, 900).seconds_left > 800


@pytest.mark.asyncio
async def test_retry_after_is_capped(monkeypatch):
    slept: list[float] = []

    async def fake_sleep(d):
        slept.append(d)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    await RetryPolicy().sleep(0, retry_after=99999)
    assert slept == [10.0]


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -5.0])
async def test_invalid_retry_after_falls_back_to_backoff(monkeypatch, bad):
    slept: list[float] = []

    async def fake_sleep(d):
        slept.append(d)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    await RetryPolicy(backoff_base=0.2).sleep(1, retry_after=bad)
    assert slept == [0.4]


@pytest.mark.asyncio
async def test_retry_sleep_raises_when_budget_shorter_than_delay():
    with pytest.raises(BudgetExceeded):
        await RetryPolicy().sleep(0, retry_after=5, budget=BudgetTracker(10, 1))


@pytest.mark.asyncio
async def test_replay_unparsable_retry_after_does_not_crash():
    for raw in ("abc", "-5", "inf"):
        calls = {"n": 0}

        def handler(request, calls=calls, raw=raw):
            calls["n"] += 1
            return httpx.Response(503, headers={"Retry-After": raw}) if calls["n"] < 2 \
                else httpx.Response(200)
        rp, sess, store = _replayer(handler, retry=RetryPolicy(backoff_base=0.01))
        resp = await rp.replay(_req(), sess)
        assert resp.status == 200
        await store.aclose_all()


@pytest.mark.asyncio
async def test_retry_after_huge_stops_quickly_via_budget():
    def handler(request):
        return httpx.Response(503, headers={"Retry-After": "99999"})
    rp, sess, store = _replayer(handler, wall=1, retry=RetryPolicy())
    t0 = time.monotonic()
    with pytest.raises(BudgetExceeded):
        await rp.replay(_req(), sess)
    assert time.monotonic() - t0 < 3
    await store.aclose_all()


@pytest.mark.asyncio
async def test_replay_hanging_request_hits_wall_clock():
    async def handler(request):
        await asyncio.sleep(30)
        return httpx.Response(200)
    rp, sess, store = _replayer(handler, wall=1)
    t0 = time.monotonic()
    with pytest.raises(BudgetExceeded):
        await rp.replay(_req(), sess)
    assert time.monotonic() - t0 < 3
    await store.aclose_all()


async def _scanner_with_hang(hang_in_phase: bool):
    async def handler(request):
        if "hang" in request.url.path:
            await asyncio.sleep(30)
        return httpx.Response(200, json={"id": "1", "email": "a@b.c"})

    scanner = Scanner(BASE, SCOPE, BudgetConfig(max_total_requests=500, max_wall_clock_sec=1,
                                                max_rps_per_host=1000))
    scanner.deadline_grace_sec = 1.0
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"open": "1", "hang": "1"}))
    scanner.anon = store.create(Actor(name="anonymous", role="anonymous"))
    hyps = [Hypothesis(type="unauthorized_access",
                       endpoint=Endpoint(method="GET", path_template=p, id_param="id"), rationale="r")
            for p in ("/api/open/{id}", "/api/hang/{id}")]

    async def gen(_eps):
        return hyps
    scanner.planner.generate = gen
    return scanner, store, A


@pytest.mark.asyncio
async def test_scan_returns_partial_and_keeps_findings_when_request_hangs():
    scanner, store, A = await _scanner_with_hang(False)
    t0 = time.monotonic()
    findings = await scanner.run_recon_scan(
        [A], [Endpoint(method="GET", path_template="/api/open/{id}", id_param="id")],
        bootstrap=False, exposure_scan=False, info_leak_scan=False, rate_limit_scan=False,
        cve_scan=False, template_scan=False, tls_scan=False)
    assert time.monotonic() - t0 < 6
    assert any("/api/open" in f.endpoint for f in findings)   # ilk bulgu kaybolmadı
    assert scanner.partial is True and scanner.stop_reason
    await store.aclose_all()


@pytest.mark.asyncio
async def test_scan_deadline_cancels_stuck_phase_and_keeps_hypothesis_findings():
    scanner, store, A = await _scanner_with_hang(False)

    async def stuck(*a, **k):   # Replayer'ı bypass eden takılı faz → yalnız toplam deadline kurtarır
        await asyncio.sleep(60)
    scanner.run_exposure_scan = stuck
    t0 = time.monotonic()
    findings = await scanner.run_recon_scan(
        [A], [Endpoint(method="GET", path_template="/api/open/{id}", id_param="id")],
        bootstrap=False, info_leak_scan=False, rate_limit_scan=False, cve_scan=False,
        template_scan=False, tls_scan=False)
    assert time.monotonic() - t0 < 6
    assert any("/api/open" in f.endpoint for f in findings)
    assert scanner.partial is True and "süre" in scanner.stop_reason
    await store.aclose_all()
