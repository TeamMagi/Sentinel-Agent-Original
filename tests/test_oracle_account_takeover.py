"""Account takeover oracle'ları: password_reset_abuse (tekrar-kullanım + zayıflık) ve
mfa_bypass (ön-koşul atlama + OTP tekrar-kullanımı) — ağsız (httpx.MockTransport)."""
from __future__ import annotations

import json

import httpx

from pentestai.models import Actor, AuthState, CapturedRequest, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle.account_takeover import MfaBypassOracle, PasswordResetAbuseOracle
from pentestai.oracle.base import CONFIRMED, INCONCLUSIVE, REJECTED
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
VALID_TOKEN = "tok-abc12345"
BOGUS_TOKEN = "tok-bogus0000"


def _scope(*, destructive: bool = True, methods=None) -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=methods or ["GET", "POST"], destructive_tests=destructive)


def _builder(token: str) -> CapturedRequest:
    return CapturedRequest(method="POST", url=f"{BASE}/api/reset-confirm",
                           headers={"Content-Type": "application/json"},
                           body=json.dumps({"token": token, "newPassword": "NewP@ss1!"}).encode())


# --- check_token_reuse ---

def _reset_confirm_app(*, kind: str) -> httpx.MockTransport:
    state = {"used": False}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        if kind == "accepts_anything":
            return httpx.Response(200, json={"success": True})
        if body.get("token") != VALID_TOKEN:
            return httpx.Response(400, json={"error": "invalid token"})
        if kind == "vuln":
            return httpx.Response(200, json={"success": True})
        if kind == "hardened":
            if state["used"]:
                return httpx.Response(410, json={"error": "token already used"})
            state["used"] = True
            return httpx.Response(200, json={"success": True})
        if kind == "near_miss":
            if state["used"]:
                return httpx.Response(200, json={"success": False, "error": "token expired"})
            state["used"] = True
            return httpx.Response(200, json={"success": True})
        raise AssertionError(kind)

    return httpx.MockTransport(handler)


async def test_token_reuse_confirmed():
    store = SessionStore(transport=_reset_confirm_app(kind="vuln"))
    victim = store.create(Actor(name="victim"))
    oracle = PasswordResetAbuseOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        f = await oracle.check_token_reuse(victim, _builder, token=VALID_TOKEN, bogus_token=BOGUS_TOKEN)
        assert f.verdict == CONFIRMED and f.confidence == "high"
        assert f.evidence.positive_control and f.evidence.negative_control
        assert VALID_TOKEN not in " ".join(f.evidence.leaked_markers)
        assert VALID_TOKEN not in (f.evidence.attack_request.body or b"").decode()
    finally:
        await store.aclose_all()


async def test_token_reuse_rejected_when_invalidated():
    store = SessionStore(transport=_reset_confirm_app(kind="hardened"))
    victim = store.create(Actor(name="victim"))
    oracle = PasswordResetAbuseOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        f = await oracle.check_token_reuse(victim, _builder, token=VALID_TOKEN, bogus_token=BOGUS_TOKEN)
        assert f.verdict == REJECTED
    finally:
        await store.aclose_all()


async def test_token_reuse_not_confirmed_on_denial_signature_near_miss():
    store = SessionStore(transport=_reset_confirm_app(kind="near_miss"))
    victim = store.create(Actor(name="victim"))
    oracle = PasswordResetAbuseOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        f = await oracle.check_token_reuse(victim, _builder, token=VALID_TOKEN, bogus_token=BOGUS_TOKEN)
        assert f.verdict != CONFIRMED
    finally:
        await store.aclose_all()


async def test_token_reuse_inconclusive_when_first_use_fails():
    store = SessionStore(transport=_reset_confirm_app(kind="vuln"))
    victim = store.create(Actor(name="victim"))
    oracle = PasswordResetAbuseOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        f = await oracle.check_token_reuse(victim, _builder, token="wrong-token")
        assert f.verdict == INCONCLUSIVE
    finally:
        await store.aclose_all()


async def test_token_reuse_inconclusive_when_negative_control_fails():
    store = SessionStore(transport=_reset_confirm_app(kind="accepts_anything"))
    victim = store.create(Actor(name="victim"))
    oracle = PasswordResetAbuseOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        f = await oracle.check_token_reuse(victim, _builder, token=VALID_TOKEN, bogus_token=BOGUS_TOKEN)
        assert f.verdict == INCONCLUSIVE
        assert "ayırt edici değil" in (f.triage_note or "")
    finally:
        await store.aclose_all()


async def test_token_reuse_inconclusive_when_policy_denies():
    store = SessionStore(transport=_reset_confirm_app(kind="vuln"))
    victim = store.create(Actor(name="victim"))
    oracle = PasswordResetAbuseOracle(Replayer(PolicyEngine(_scope(destructive=False))), BASE)
    try:
        f = await oracle.check_token_reuse(victim, _builder, token=VALID_TOKEN)
        assert f.verdict == INCONCLUSIVE
    finally:
        await store.aclose_all()


# --- check_token_weakness ---

async def _weakness(tokens):
    oracle = PasswordResetAbuseOracle(Replayer(PolicyEngine(_scope())), BASE)
    return await oracle.check_token_weakness(tokens)


async def test_token_weakness_inconclusive_insufficient_samples():
    f = await _weakness(["123456"])
    assert f.verdict == INCONCLUSIVE
    assert "yetersiz" in (f.triage_note or "")


async def test_token_weakness_confirmed_short_digit_pin():
    f = await _weakness(["1234", "5678", "0099"])
    assert f.verdict == CONFIRMED
    assert "kısa sayısal" in f.evidence.leaked_markers[0]


async def test_token_weakness_confirmed_sequential():
    f = await _weakness(["1000001", "1000002", "1000003"])
    assert f.verdict == CONFIRMED
    assert "ardışık" in f.evidence.leaked_markers[0]


async def test_token_weakness_confirmed_timestamp_like():
    import time
    now = int(time.time())
    f = await _weakness([str(now), str(now + 7), str(now + 13)])
    assert f.verdict == CONFIRMED
    assert "timestamp" in f.evidence.leaked_markers[0].lower()


async def test_token_weakness_inconclusive_high_entropy():
    f = await _weakness(["9f86d081884c7d659a2feaa0c55ad015", "a3bf4f1b2b0b822cd15d6c15b0f00a1e"])
    assert f.verdict != CONFIRMED


async def test_token_weakness_not_confirmed_short_but_high_entropy_charset():
    """Near-miss desen: 8 karakterlik ama karışık karakter setiyle (rastgele) token — CONFIRMED
    olmamalı (charset-tabanlı tahmini bit eşiğin üstünde, Shannon per-char de düşük değil)."""
    f = await _weakness(["aK9#mZ2!", "qT4$xW7&", "bN0@pL5%"])
    assert f.verdict != CONFIRMED


# --- check_precondition_bypass ---

def _mfa_app(*, kind: str) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if kind == "public":
            return httpx.Response(200, json={"banner": "public"})
        if kind == "vuln":
            if auth in ("Bearer PRE", "Bearer FULL"):
                return httpx.Response(200, json={"id": 1, "email": "victim@test.local"})
            return httpx.Response(401, json={"error": "unauthorized"})
        if kind == "hardened":
            if auth == "Bearer FULL":
                return httpx.Response(200, json={"id": 1})
            return httpx.Response(401, json={"error": "2fa required"})
        if kind == "authed_broken":
            return httpx.Response(500, json={"error": "boom"})
        raise AssertionError(kind)

    return httpx.MockTransport(handler)


_EP = Endpoint(method="GET", path_template="/api/me")


async def test_mfa_precondition_confirmed():
    store = SessionStore(base_url=BASE, transport=_mfa_app(kind="vuln"))
    pre = store.create(Actor(name="pre", auth=AuthState(headers={"Authorization": "Bearer PRE"})))
    full = store.create(Actor(name="full", auth=AuthState(headers={"Authorization": "Bearer FULL"})))
    anon = store.create(Actor(name="anon"))
    oracle = MfaBypassOracle(Replayer(PolicyEngine(_scope(methods=["GET"]))), BASE)
    try:
        f = await oracle.check_precondition_bypass(_EP, pre, anon_session=anon, authed_session=full)
        assert f.verdict == CONFIRMED and f.confidence == "high"
        assert f.evidence.positive_control and f.evidence.negative_control
    finally:
        await store.aclose_all()


async def test_mfa_precondition_rejected_when_enforced():
    store = SessionStore(base_url=BASE, transport=_mfa_app(kind="hardened"))
    pre = store.create(Actor(name="pre", auth=AuthState(headers={"Authorization": "Bearer PRE"})))
    full = store.create(Actor(name="full", auth=AuthState(headers={"Authorization": "Bearer FULL"})))
    anon = store.create(Actor(name="anon"))
    oracle = MfaBypassOracle(Replayer(PolicyEngine(_scope(methods=["GET"]))), BASE)
    try:
        f = await oracle.check_precondition_bypass(_EP, pre, anon_session=anon, authed_session=full)
        assert f.verdict == REJECTED
    finally:
        await store.aclose_all()


async def test_mfa_precondition_inconclusive_when_public_by_design():
    store = SessionStore(base_url=BASE, transport=_mfa_app(kind="public"))
    pre = store.create(Actor(name="pre", auth=AuthState(headers={"Authorization": "Bearer PRE"})))
    anon = store.create(Actor(name="anon"))
    oracle = MfaBypassOracle(Replayer(PolicyEngine(_scope(methods=["GET"]))), BASE)
    try:
        f = await oracle.check_precondition_bypass(_EP, pre, anon_session=anon)
        assert f.verdict == INCONCLUSIVE
        assert "public-by-design" in (f.triage_note or "")
    finally:
        await store.aclose_all()


async def test_mfa_precondition_inconclusive_when_positive_control_fails():
    store = SessionStore(base_url=BASE, transport=_mfa_app(kind="authed_broken"))
    pre = store.create(Actor(name="pre", auth=AuthState(headers={"Authorization": "Bearer PRE"})))
    full = store.create(Actor(name="full", auth=AuthState(headers={"Authorization": "Bearer FULL"})))
    oracle = MfaBypassOracle(Replayer(PolicyEngine(_scope(methods=["GET"]))), BASE)
    try:
        f = await oracle.check_precondition_bypass(_EP, pre, authed_session=full)
        assert f.verdict == INCONCLUSIVE
        assert "temel kuramsal zemin" in (f.triage_note or "")
    finally:
        await store.aclose_all()


# --- check_otp_replay ---

def _otp_verify_builder(otp: str) -> CapturedRequest:
    return CapturedRequest(method="POST", url=f"{BASE}/api/otp/verify",
                           headers={"Content-Type": "application/json"},
                           body=json.dumps({"otp": otp}).encode())


def _otp_app(*, kind: str) -> httpx.MockTransport:
    state = {"used": False}
    valid_otp = "445566"

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        if body.get("otp") != valid_otp:
            return httpx.Response(400, json={"error": "invalid otp"})
        if kind == "vuln":
            return httpx.Response(200, json={"success": True})
        if kind == "hardened":
            if state["used"]:
                return httpx.Response(401, json={"error": "otp expired"})
            state["used"] = True
            return httpx.Response(200, json={"success": True})
        raise AssertionError(kind)

    return httpx.MockTransport(handler)


async def test_otp_replay_confirmed():
    store = SessionStore(transport=_otp_app(kind="vuln"))
    session = store.create(Actor(name="victim"))
    oracle = MfaBypassOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        f = await oracle.check_otp_replay(session, _otp_verify_builder, otp="445566",
                                          bogus_otp="000000")
        assert f.verdict == CONFIRMED
        assert "445566" not in " ".join(f.evidence.leaked_markers)
    finally:
        await store.aclose_all()


async def test_otp_replay_rejected_when_single_use():
    store = SessionStore(transport=_otp_app(kind="hardened"))
    session = store.create(Actor(name="victim"))
    oracle = MfaBypassOracle(Replayer(PolicyEngine(_scope())), BASE)
    try:
        f = await oracle.check_otp_replay(session, _otp_verify_builder, otp="445566",
                                          bogus_otp="000000")
        assert f.verdict == REJECTED
    finally:
        await store.aclose_all()
