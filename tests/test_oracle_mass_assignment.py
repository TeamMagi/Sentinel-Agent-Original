"""MassAssignmentOracle — fazla alan (role/isAdmin) set oluyor mu? B1."""
import copy
import json

import httpx
import pytest

from pentestai.models import Actor, Endpoint, NormalizedResponse, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.mass_assignment import MassAssignmentOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="PUT", path_template="/api/users/{id}", id_param="id")


def make_app(*, whitelisted: bool):
    """`whitelisted=False` → sunucu body'deki HER alanı körlemesine bind eder (vulnerable)."""
    db = {"U-1": {"id": "U-1", "quantity": 1, "role": "user"}}
    allowed_fields = {"quantity"}

    def handler(request):
        oid = request.url.path.rsplit("/", 1)[-1]
        obj = db.get(oid)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if request.method == "GET":
            return httpx.Response(200, json=obj)
        body = json.loads(request.content or b"{}")
        if whitelisted:
            obj.update({k: v for k, v in body.items() if k in allowed_fields})
        else:
            obj.update(body)   # ownership/whitelisting YOK — mass assignment
        return httpx.Response(200, json=obj)

    return handler


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "PUT"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", own_object_ids={"user": "U-1"})
    oracle = MassAssignmentOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A)


@pytest.mark.asyncio
async def test_confirmed_when_privilege_field_accepted():
    store, oracle, A = _setup(make_app(whitelisted=False))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("role" in m for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_server_whitelists_fields():
    store, oracle, A = _setup(make_app(whitelisted=True))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_already_privileged():
    # negatif kontrol: saldırgan zaten role=admin ise trivial false-positive olmasın
    def handler(request):
        oid = request.url.path.rsplit("/", 1)[-1]
        if request.method == "GET":
            return httpx.Response(200, json={"id": oid, "quantity": 1, "role": "admin"})
        return httpx.Response(200, json={"id": oid, "quantity": 1, "role": "admin"})

    store, oracle, A = _setup(handler)
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_attacker_id_missing():
    store, oracle, A = _setup(make_app(whitelisted=False))
    A.actor.own_object_ids.clear()
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_without_id_endpoint():
    store, oracle, A = _setup(make_app(whitelisted=False))
    ep_no_id = Endpoint(method="PUT", path_template="/api/settings", id_param="id")
    f = await oracle.run(ep_no_id, A, A, resource_key="user")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


# --- GÖREV 4: şemadan öğrenme, iç-içe alan, allow-list, geri alma ---

def _deep_merge(dst, src):
    """Test handler'ı için iç-içe birleştirme (vulnerable sunucu davranışı)."""
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _deep_merge(dst[key], value)
        else:
            dst[key] = value


def _stateful_app(initial, *, apply="all", reject_after=None):
    """Durum-bilgili handler: GET kalıcı objeyi döner; PUT gövdeyi moda göre uygular."""
    state = {"obj": copy.deepcopy(initial), "writes": 0}

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=copy.deepcopy(state["obj"]))
        state["writes"] += 1
        if reject_after is not None and state["writes"] > reject_after:
            return httpx.Response(403, json={"error": "forbidden"})
        body = json.loads(request.content or b"{}")
        if apply == "all":
            _deep_merge(state["obj"], body)
        elif apply == "name" and "name" in body:
            state["obj"]["name"] = body["name"]
        return httpx.Response(200, json={"status": "ok"})

    return handler


@pytest.mark.asyncio
async def test_nested_learned_field_accepted_confirmed():
    initial = {"id": "U-1", "name": "alice", "profile": {"role": "user"}}
    store, oracle, A = _setup(_stateful_app(initial))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("profile.role" in m and "şemadan öğrenildi" in m
               for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_field_allow_list_proven_when_only_name_persists():
    initial = {"id": "U-1", "name": "alice", "profile": {"role": "user"}}
    store, oracle, A = _setup(_stateful_app(initial, apply="name"))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.REJECTED
    assert f.triage_note is not None and "field allow-list çalışıyor" in f.triage_note
    await store.aclose_all()


@pytest.mark.asyncio
async def test_numeric_learned_field_accepted_confirmed():
    initial = {"id": "U-1", "name": "alice", "credit": 10}
    store, oracle, A = _setup(_stateful_app(initial))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("credit" in m for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_str_user_id_is_not_a_candidate():
    initial = {"id": "U-1", "name": "alice", "user_id": "U-1"}
    store, oracle, A = _setup(_stateful_app(initial))
    f = await oracle.run(EP, A, A, resource_key="user")
    body = json.loads(f.evidence.attack_request.body or b"{}")
    assert "user_id" not in body
    await store.aclose_all()


@pytest.mark.asyncio
async def test_cosmetic_write_rejected():
    initial = {"id": "U-1", "name": "alice", "role": "user"}
    store, oracle, A = _setup(_stateful_app(initial, apply="none"))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.REJECTED
    assert f.triage_note is not None and "yazma yolu doğrulanamadı" in f.triage_note
    await store.aclose_all()


@pytest.mark.asyncio
async def test_restore_succeeds_when_handler_accepts_rewrite():
    initial = {"id": "U-1", "name": "alice", "role": "user"}
    store, oracle, A = _setup(_stateful_app(initial))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.restored is True
    await store.aclose_all()


@pytest.mark.asyncio
async def test_restore_failure_recorded_without_changing_verdict():
    initial = {"id": "U-1", "name": "alice", "role": "user"}
    store, oracle, A = _setup(_stateful_app(initial, reject_after=1))
    f = await oracle.run(EP, A, A, resource_key="user")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.restored is False
    assert f.evidence.recovery_state is not None
    assert f.evidence.recovery_state["reason"] == "geri alma doğrulanamadı"
    await store.aclose_all()


def test_field_set_is_structural():
    nested = NormalizedResponse(status=200, json_body={"a": {"role": "admin"}})
    assert MassAssignmentOracle._field_set(nested, "role", "admin") is True
    plain = NormalizedResponse(status=200, json_body={"role": "user"})
    assert MassAssignmentOracle._field_set(plain, "role", "admin") is False
    fallback = NormalizedResponse(status=200, body_normalized='"role": "admin"', json_body=None)
    assert MassAssignmentOracle._field_set(fallback, "role", "admin") is True


@pytest.mark.asyncio
async def test_learn_candidates_conversions_and_depth_limit():
    store, oracle, _A = _setup(make_app(whitelisted=False))
    learned = oracle._learn_candidates({
        "role": "user",
        "is_admin": False,
        "credit": 10,
        "wallet": None,
        "user_id": "U-1",
        "profile": {"tier": "free"},
        "a": {"b": {"c": {"role": "user"}}},
    })
    by_path = {".".join(path): (old, new) for path, old, new in learned}
    assert by_path["role"] == ("user", "admin")
    assert by_path["is_admin"] == (False, True)
    assert by_path["credit"] == (10, 1010)
    assert by_path["wallet"] == (None, True)
    assert by_path["profile.tier"] == ("free", "admin")
    assert "user_id" not in by_path          # str id → başka kullanıcı id'si uydurulmaz
    assert "a.b.c.role" not in by_path        # 4. seviye öğrenilmez
    await store.aclose_all()


@pytest.mark.asyncio
async def test_numeric_ownership_fields_are_never_candidates():
    """Güvenlik: int owner_id/user_id değiştirilirse obje başka gerçek kullanıcıya devredilirdi."""
    store, oracle, _A = _setup(make_app(whitelisted=False))
    learned = oracle._learn_candidates({"user_id": 42, "ownerId": 7, "owner_id": 9, "credit": 10})
    paths = {".".join(path) for path, _old, _new in learned}
    assert paths == {"credit"}
    await store.aclose_all()
