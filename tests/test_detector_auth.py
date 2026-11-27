"""Auth dedektörleri (A6) — JWT zafiyetleri + kullanıcı enümerasyonu.

Sahte hedef: JWT'yi ya hiç doğrulamaz (vuln) ya da güçlü secret ile HMAC doğrular (secure).
Enümerasyon: geçerli/geçersiz kullanıcıya farklı yanıt verir. Kanıt gözlenendir. Network yok.
"""
import hmac
import json

import httpx
import pytest

from pentestai.detector.auth_probes import (
    JwtDetector,
    UserEnumDetector,
    _b64url_decode,
    _b64url_encode,
    _hs256,
)
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
STRONG_SECRET = "S9x!v3ry-l0ng-r4nd0m-secret-not-in-any-wordlist"
PROTECTED = Endpoint(method="GET", path_template="/api/me")
LOGIN = Endpoint(method="GET", path_template="/api/login")
BASKET = Endpoint(method="GET", path_template="/rest/basket/{id}")   # id'li uç (Juice Shop)


def _make_jwt(payload: dict, secret: str) -> str:
    header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    return f"{signing_input}.{_hs256(signing_input.encode(), secret)}"


def _setup(handler, token: str | None, own_object_ids: dict | None = None):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    s = store.create(Actor(name="user_A", auth=AuthState(headers=headers),
                           own_object_ids=own_object_ids or {}))
    return store, JwtDetector(Replayer(PolicyEngine(scope)), BASE), s


# --- JWT ---

def jwt_vuln(request):
    """İmzayı hiç doğrulamayan sunucu — herhangi bir Bearer token'ı kabul eder."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer ") or auth[7:].count(".") != 2:
        return httpx.Response(401, json={"error": "no token"})
    return httpx.Response(200, json={"user": "ok"})


def jwt_secure(request):
    """HS256 imzayı güçlü secret ile doğrulayan sunucu."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return httpx.Response(401, json={"error": "no token"})
    parts = auth[7:].split(".")
    if len(parts) != 3:
        return httpx.Response(401, json={"error": "malformed"})
    h, p, s = parts
    try:
        header = json.loads(_b64url_decode(h))
    except Exception:
        return httpx.Response(401, json={"error": "bad header"})
    if header.get("alg") != "HS256":
        return httpx.Response(401, json={"error": "alg"})
    if not hmac.compare_digest(_hs256(f"{h}.{p}".encode(), STRONG_SECRET), s):
        return httpx.Response(401, json={"error": "sig"})
    return httpx.Response(200, json={"user": "ok"})


@pytest.mark.asyncio
async def test_jwt_confirmed_when_signature_not_verified():
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    store, det, s = _setup(jwt_vuln, token)
    fs = await det.run(PROTECTED, s)
    await store.aclose_all()
    verdicts = {f.parameter: f.verdict for f in fs}
    assert verdicts["alg=none"] == base.CONFIRMED
    assert verdicts["signature"] == base.CONFIRMED
    assert verdicts["weak-secret"] == base.CONFIRMED


def jwt_public(request):
    """Token'a hiç bakmayan herkese açık uç (/healthcheck): token'sız istek de 200."""
    return httpx.Response(200, json={"status": "ok"})


@pytest.mark.asyncio
async def test_jwt_public_endpoint_not_confirmed():
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    store, det, s = _setup(jwt_public, token)
    fs = await det.run(PROTECTED, s)
    await store.aclose_all()
    assert {f.parameter for f in fs} == {"alg=none", "signature", "weak-secret"}
    assert all(f.verdict == base.REJECTED for f in fs)
    assert all("token-suz da erişilebilir" in (f.triage_note or "") for f in fs)
    # aktörün token'ı anonim kontrolden sonra yerinde kalmalı
    assert s.actor.auth.headers["Authorization"] == f"Bearer {token}"


@pytest.mark.asyncio
async def test_jwt_protected_endpoint_still_confirmed_alg_none():
    """Korumalı uç (anonim=401) imzayı doğrulamıyorsa CONFIRMED davranışı korunur."""
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    store, det, s = _setup(jwt_vuln, token)
    fs = await det.run(PROTECTED, s)
    await store.aclose_all()
    assert next(f for f in fs if f.parameter == "alg=none").verdict == base.CONFIRMED


@pytest.mark.asyncio
async def test_jwt_rejected_when_properly_verified():
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    store, det, s = _setup(jwt_secure, token)
    fs = await det.run(PROTECTED, s)
    await store.aclose_all()
    assert all(f.verdict == base.REJECTED for f in fs)


@pytest.mark.asyncio
async def test_jwt_confirmed_on_weak_secret():
    token = _make_jwt({"sub": "user_A"}, "secret")   # zayıf secret listede
    store, det, s = _setup(jwt_secure_weak, token)
    fs = await det.run(PROTECTED, s)
    await store.aclose_all()
    weak = next(f for f in fs if f.parameter == "weak-secret")
    assert weak.verdict == base.CONFIRMED


def jwt_secure_weak(request):
    """HS256'yı 'secret' (zayıf) ile doğrular — forge edilebilir."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return httpx.Response(401)
    parts = auth[7:].split(".")
    if len(parts) != 3:
        return httpx.Response(401)
    h, p, s = parts
    try:
        if json.loads(_b64url_decode(h)).get("alg") != "HS256":
            return httpx.Response(401)
    except Exception:
        return httpx.Response(401)
    if not hmac.compare_digest(_hs256(f"{h}.{p}".encode(), "secret"), s):
        return httpx.Response(401)
    return httpx.Response(200, json={"user": "ok"})


@pytest.mark.asyncio
async def test_jwt_skipped_when_no_token():
    store, det, s = _setup(jwt_vuln, None)
    fs = await det.run(PROTECTED, s)
    await store.aclose_all()
    assert fs == []   # JWT yoksa sessizce atla


# --- User enumeration ---

VALID = "alice@example.com"
INVALID = "nope-9f3a2b@example.com"


def enum_vuln(request):
    email = request.url.params.get("email", "")
    if email == VALID:
        return httpx.Response(401, json={"error": "wrong password"})
    return httpx.Response(404, json={"error": "user not found"})


def enum_safe(request):
    return httpx.Response(401, json={"error": "invalid credentials"})


async def _run_enum(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A"))
    det = UserEnumDetector(Replayer(PolicyEngine(scope)), BASE,
                           valid_user=VALID, invalid_user=INVALID)
    fs = await det.run(LOGIN, s)
    await store.aclose_all()
    return fs[0]


@pytest.mark.asyncio
async def test_user_enum_confirmed_on_differential():
    f = await _run_enum(enum_vuln)
    assert f.verdict == base.CONFIRMED
    assert f.evidence.leaked_markers   # differential türü (kullanıcı adı/email YAZILMAZ)
    assert VALID not in " ".join(f.evidence.leaked_markers)   # redaction


@pytest.mark.asyncio
async def test_user_enum_rejected_when_identical():
    f = await _run_enum(enum_safe)
    assert f.verdict == base.REJECTED


@pytest.mark.asyncio
async def test_jwt_public_endpoint_lowercase_authorization_header():
    """Başlık adı küçük harfli (`authorization`) olsa da anonim kontrol onu kaldırmalı → REJECTED."""
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    seen: list[bool] = []

    def handler(request):
        seen.append("authorization" in request.headers)
        return httpx.Response(200, json={"status": "ok"})
    store2, det2, s2 = _setup(handler, token)
    s2.actor.auth.headers.clear()
    s2.actor.auth.headers["authorization"] = f"Bearer {token}"
    fs = await det2.run(PROTECTED, s2)
    await store2.aclose_all()
    assert all(f.verdict == base.REJECTED for f in fs)
    assert False in seen                       # anonim istekte başlık gerçekten yoktu
    assert s2.actor.auth.headers == {"authorization": f"Bearer {token}"}


# --- id'li uç (/rest/basket/{id}) — own_object_ids ile somut id kurulmalı (literal {id} gitmez) ---

def _basket_vuln_factory(seen_paths: list[str]):
    """İmzayı hiç doğrulamayan, token İSTEYEN sunucu — id'li kaynağı döner."""
    def handler(request):
        seen_paths.append(request.url.path)
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer ") or auth[7:].count(".") != 2:
            return httpx.Response(401, json={"error": "no token"})
        return httpx.Response(200, json={"id": 7, "products": []})
    return handler


def _basket_secure_factory(seen_paths: list[str]):
    """HS256 imzayı güçlü secret ile doğrulayan sunucu (id'li kaynak)."""
    def handler(request):
        seen_paths.append(request.url.path)
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return httpx.Response(401, json={"error": "no token"})
        parts = auth[7:].split(".")
        if len(parts) != 3:
            return httpx.Response(401, json={"error": "malformed"})
        h, p, s = parts
        try:
            header = json.loads(_b64url_decode(h))
        except Exception:
            return httpx.Response(401, json={"error": "bad header"})
        if header.get("alg") != "HS256":
            return httpx.Response(401, json={"error": "alg"})
        if not hmac.compare_digest(_hs256(f"{h}.{p}".encode(), STRONG_SECRET), s):
            return httpx.Response(401, json={"error": "sig"})
        return httpx.Response(200, json={"id": 7, "products": []})
    return handler


def _basket_public_factory(seen_paths: list[str]):
    """Token'a hiç bakmayan herkese açık id'li uç — anonim de aynı 200'ü alır."""
    def handler(request):
        seen_paths.append(request.url.path)
        return httpx.Response(200, json={"id": 7, "products": []})
    return handler


@pytest.mark.asyncio
async def test_jwt_id_endpoint_uses_own_object_id_not_literal_placeholder():
    """id'li uçta istek own_object_ids'teki GERÇEK id ile kurulur; literal '{id}' gitmez."""
    seen: list[str] = []
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    store, det, s = _setup(_basket_vuln_factory(seen), token, own_object_ids={"basket": "7"})
    fs = await det.run(BASKET, s)
    await store.aclose_all()
    assert seen and all(p == "/rest/basket/7" for p in seen)
    assert all("{id}" not in p for p in seen)
    verdicts = {f.parameter: f.verdict for f in fs}
    assert verdicts["alg=none"] == base.CONFIRMED
    assert verdicts["signature"] == base.CONFIRMED
    assert verdicts["weak-secret"] == base.CONFIRMED


@pytest.mark.asyncio
async def test_jwt_id_endpoint_rejected_when_properly_verified():
    seen: list[str] = []
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    store, det, s = _setup(_basket_secure_factory(seen), token, own_object_ids={"basket": "7"})
    fs = await det.run(BASKET, s)
    await store.aclose_all()
    assert seen and all(p == "/rest/basket/7" for p in seen)
    assert all(f.verdict == base.REJECTED for f in fs)


@pytest.mark.asyncio
async def test_jwt_id_endpoint_public_rejected_not_confirmed():
    seen: list[str] = []
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    store, det, s = _setup(_basket_public_factory(seen), token, own_object_ids={"basket": "7"})
    fs = await det.run(BASKET, s)
    await store.aclose_all()
    assert all(f.verdict == base.REJECTED for f in fs)
    assert all("token-suz da erişilebilir" in (f.triage_note or "") for f in fs)


@pytest.mark.asyncio
async def test_jwt_id_endpoint_inconclusive_when_own_id_unknown():
    """Aktörün bu kaynakta kendi id'si bilinmiyorsa (own_object_ids boş) INCONCLUSIVE döner."""
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    store, det, s = _setup(_basket_vuln_factory([]), token, own_object_ids={})
    fs = await det.run(BASKET, s)
    await store.aclose_all()
    assert len(fs) == 1
    assert fs[0].verdict == base.INCONCLUSIVE
    assert "bilinmiyor" in (fs[0].triage_note or "")


@pytest.mark.asyncio
async def test_jwt_anonymous_scope_error_does_not_confirm():
    """Anonim istek ScopeError verirse negatif kontrol yok sayılır; aktör header'ı bozulmaz."""
    token = _make_jwt({"sub": "user_A", "role": "user"}, STRONG_SECRET)
    store, det, s = _setup(jwt_public, token)

    class _Raising:
        def __init__(self, inner):
            self.inner, self.n = inner, 0

        async def replay(self, req, session):
            self.n += 1
            if self.n == 2:                      # 1: baseline, 2: anonim kontrol
                from pentestai.net.replay import ScopeError
                raise ScopeError("kapsam dışı")
            return await self.inner.replay(req, session)
    det.replayer = _Raising(det.replayer)
    fs = await det.run(PROTECTED, s)
    await store.aclose_all()
    assert fs                                    # çökmedi
    assert s.actor.auth.headers == {"Authorization": f"Bearer {token}"}
