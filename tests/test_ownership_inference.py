"""Sahiplik çıkarımı (R-B3) — own_object_ids'i ELLE vermeden bootstrap. Network yok.

- canonical_resource_key / OwnObjectIds: tekil/çoğul + harf duyarsız anahtar
  (`/api/Users/{id}` → 'users' ile JWT'den gelen 'user' aynı kaynağa düşer).
- jwt_payload + infer_resource_ids: Juice Shop biçimli JWT'den kullanıcı id'si ('data' değil).
- CrawlRecon / Scanner._bootstrap_ids: whoami boşsa Bearer JWT; kimlik koleksiyonu crawl
  edilmez; ortak (public) ilk id'ler düşer; config her zaman önceliklidir.
Yanlış çıkarılmış own-id'nin verdict'e etkisi (INCONCLUSIVE) oracle'ın kendi testindedir:
tests/test_oracle_idor.py::test_inconclusive_when_victim_cannot_read_own_object.
"""
import base64
import json
from types import SimpleNamespace

import httpx
import pytest

from pentestai.models import (
    Actor,
    AuthState,
    Endpoint,
    OwnObjectIds,
    Scope,
    canonical_resource_key,
)
from pentestai.net import Replayer, SessionStore
from pentestai.orchestrator.idtools import infer_resource_ids, jwt_payload
from pentestai.policy import PolicyEngine
from pentestai.recon.crawl import CrawlRecon
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
SCOPE = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _jwt(payload: dict) -> str:
    return f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}.{_b64(payload)}.sig"


def _juice_jwt(uid: int, email: str) -> dict:
    """Juice Shop login token'ının gövde biçimi (canlıda doğrulanan anahtar kümesi)."""
    return {
        "status": "success",
        "data": {"id": uid, "username": "", "email": email, "password": "<hash>",
                 "role": "customer", "deluxeToken": "", "lastLoginIp": "0.0.0.0",
                 "profileImage": "/assets/default.svg", "totpSecret": "", "isActive": True},
        "bid": 6, "iat": 1700000000,
    }


# ---------------- kanonik kaynak anahtarı ----------------

@pytest.mark.parametrize("plural,singular", [
    ("users", "user"), ("Users", "user"), ("orders", "order"), ("categories", "category"),
    ("addresses", "address"), ("statuses", "status"), ("classes", "class"), ("boxes", "box"),
    ("matches", "match"), ("responses", "response"),
    # naif kuralların bozduğu biçimler: tekil ile çoğul AYNI anahtara düşmeli
    ("sizes", "size"), ("prizes", "prize"), ("caches", "cache"), ("niches", "niche"),
    ("quizzes", "quiz"),
])
def test_plural_and_singular_share_one_key(plural, singular):
    assert canonical_resource_key(plural) == canonical_resource_key(singular) == singular


@pytest.mark.parametrize("word", [
    "status", "address", "analysis", "access", "news", "series", "bus", "basket", "id",
])
def test_singular_words_ending_in_s_are_preserved(word):
    assert canonical_resource_key(word) == word


def test_own_object_ids_matches_plural_endpoint_key():
    ids = OwnObjectIds({"user": "25"})
    ep = Endpoint(method="GET", path_template="/api/Users/{id}", id_param="id")
    assert ep.resource_key in ids                     # 'Users' ↔ 'user'
    assert ids.get("users") == ids["USERS"] == "25"


# ---------------- JWT'den kimlik çıkarımı ----------------

def test_juice_shop_jwt_yields_user_id_not_data_key():
    out = infer_resource_ids(jwt_payload(_jwt(_juice_jwt(25, "victim@test.local"))))
    assert out == {"user": "25"}                      # 'data' kaynak adı sanılmaz


@pytest.mark.parametrize("token", [
    None, "", "abc", "a..c", "a.!!!.c", f"a.{_b64([1, 2])}.c", f"a.{_b64('str')}.c",
])
def test_jwt_payload_rejects_malformed_tokens(token):
    assert jwt_payload(token) is None                 # asla exception sızdırmaz


# ---------------- CrawlRecon ----------------

@pytest.mark.asyncio
async def test_feedback_bootstrap_falls_back_to_bearer_jwt_when_whoami_empty():
    # Juice Shop: whoami cookie tabanlı → Bearer ile {"user": {}} döner (canlıda gözlendi).
    def handler(request):
        if request.url.path == "/rest/user/whoami":
            return httpx.Response(200, json={"user": {}})
        return httpx.Response(404, json={})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    token = _jwt(_juice_jwt(25, "victim@test.local"))
    s = store.create(Actor(name="victim", auth=AuthState(headers={"Authorization": f"Bearer {token}"})))
    found = await CrawlRecon(Replayer(PolicyEngine(SCOPE)), BASE).feedback_bootstrap(s)
    await store.aclose_all()
    assert found == {"user": "25"}


@pytest.mark.asyncio
async def test_identity_collection_is_not_crawled_and_known_keys_are_skipped():
    seen: list[str] = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path == "/api/Users":          # herkesin listesi; ilk eleman admin
            return httpx.Response(200, json={"data": [{"id": 1, "email": "admin@x"}, {"id": 25}]})
        if request.url.path == "/api/orders":
            return httpx.Response(200, json={"data": [{"id": "O-1"}]})
        return httpx.Response(404, json={})

    eps = [Endpoint(method="GET", path_template="/api/Users/{id}", id_param="id"),
           Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"),
           Endpoint(method="GET", path_template="/api/baskets/{id}", id_param="id")]
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="a", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"basket": "CFG-1"}))
    found = await CrawlRecon(Replayer(PolicyEngine(SCOPE)), BASE).bootstrap_own_ids(s, eps)
    await store.aclose_all()
    assert "/api/Users" not in seen                   # kimlik koleksiyonu gezilmedi
    assert "/api/baskets" not in seen                 # config'te bilinen kaynak gezilmedi
    assert found == {"orders": "O-1"}


# ---------------- Scanner._bootstrap_ids (uçtan uca, ağsız) ----------------

def _bootstrap_app(request):
    tok = request.headers.get("authorization", "").replace("Bearer ", "")
    actor = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))["data"]["email"]
    p = request.url.path
    if p == "/api/profiles":                          # aktöre özel liste → farklı id'ler
        return httpx.Response(200, json=[{"id": "P-" + actor[0]}])
    if p == "/api/products":                          # ortak public liste → herkeste aynı ilk id
        return httpx.Response(200, json=[{"id": 1}, {"id": 2}])
    if p == "/api/Users":
        return httpx.Response(200, json=[{"id": 1}, {"id": 2}])
    return httpx.Response(404, json={})


async def _run_bootstrap(actors: list[Actor]) -> list:
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_bootstrap_app))
    sessions = [store.create(a) for a in actors]
    fake = SimpleNamespace(crawl=CrawlRecon(Replayer(PolicyEngine(SCOPE)), BASE),
                           _drop_shared_bootstrap_ids=Scanner._drop_shared_bootstrap_ids)
    eps = [Endpoint(method="GET", path_template=t, id_param="id")
           for t in ("/api/Users/{id}", "/api/profiles/{id}", "/api/products/{id}")]
    await Scanner._bootstrap_ids(fake, sessions, eps)
    await store.aclose_all()
    return [dict(s.actor.own_object_ids) for s in sessions]


def _actor(name: str, uid: int, email: str, **kw) -> Actor:
    token = _jwt(_juice_jwt(uid, email))
    return Actor(name=name, auth=AuthState(headers={"Authorization": f"Bearer {token}"}), **kw)


@pytest.mark.asyncio
async def test_bootstrap_without_config_finds_user_and_private_ids_drops_shared():
    a, b = await _run_bootstrap([_actor("victim", 25, "v@t.local"),
                                 _actor("attacker", 26, "a@t.local")])
    assert a == {"user": "25", "profile": "P-v"}      # JWT'den kullanıcı + özel koleksiyon
    assert b == {"user": "26", "profile": "P-a"}
    # /api/products'ın ortak ilk elemanı (1) "own" sayılmadı; /api/Users hiç crawl edilmedi.


@pytest.mark.asyncio
async def test_bootstrap_never_overrides_config_and_keeps_shared_config_key():
    a, b = await _run_bootstrap([
        _actor("victim", 25, "v@t.local", own_object_ids={"users": "CFG-V", "products": "1"}),
        _actor("attacker", 26, "a@t.local"),
    ])
    assert a["user"] == "CFG-V"                       # config, JWT çıkarımını ezer
    # victim'de config'ten gelen 'product' korunur; attacker'ın crawl'den aldığı aynı değer de
    # korunur (bir aktörde config varsa ortak anahtar komple korunur).
    assert a["product"] == "1" and b["product"] == "1"


def test_actor_without_config_ids_still_normalizes_keys():
    """Pydantic varsayılanı validator'dan geçirmez; default_factory OwnObjectIds olmalı —
    yoksa config'siz aktörde (bootstrap'ın asıl senaryosu) 'user' ≠ 'users' olurdu."""
    actor = Actor(name="x")
    assert isinstance(actor.own_object_ids, OwnObjectIds)
    actor.own_object_ids.setdefault("user", "25")
    assert "Users" in actor.own_object_ids
