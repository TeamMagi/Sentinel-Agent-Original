"""InjectionOracle — reflected XSS + error-based SQLi. DESIGN.md §14.

Sahte hedef, path'e enjekte edilen değeri yansıtır/hata verir. Kanıt gözlenendir.
"""
import html
import re
from urllib.parse import unquote

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.injection import InjectionOracle
from pentestai.policy import PolicyEngine

ENDPOINT = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
BASE = "http://localhost:3000"


def _injected(request):
    return unquote(str(request.url)).split("/api/orders/", 1)[-1]


def xss_vuln(request):       # ham yansıma, HTML
    return httpx.Response(200, headers={"content-type": "text/html"},
                         text=f"<html>Aranan: {_injected(request)}</html>")


def xss_safe(request):       # escape edilmiş
    return httpx.Response(200, headers={"content-type": "text/html"},
                         text=f"<html>Aranan: {html.escape(_injected(request))}</html>")


def sqli_vuln(request):      # tek tırnakta SQL hatası
    val = _injected(request)
    if "'" in val:
        return httpx.Response(500, text='SQLITE_ERROR: near "\'": syntax error')
    return httpx.Response(200, json={"id": val})


def sqli_safe(request):
    return httpx.Response(200, json={"id": _injected(request)})


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    return store, InjectionOracle(Replayer(PolicyEngine(scope)), BASE), s


async def _find(handler, vtype):
    store, oracle, s = _setup(handler)
    fs = await oracle.test_param(ENDPOINT, s, param="id", location="path")
    await store.aclose_all()
    return next(f for f in fs if f.type == vtype)


@pytest.mark.asyncio
async def test_xss_confirmed_when_reflected_unescaped():
    f = await _find(xss_vuln, "xss")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers   # yansıyan marker kaydedildi


@pytest.mark.asyncio
async def test_xss_rejected_when_escaped():
    f = await _find(xss_safe, "xss")
    assert f.verdict == base.REJECTED


@pytest.mark.asyncio
async def test_sqli_confirmed_on_error_differential():
    f = await _find(sqli_vuln, "sqli")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.negative_control is True   # benign temizdi, tırnak hata verdi


@pytest.mark.asyncio
async def test_sqli_rejected_without_error():
    f = await _find(sqli_safe, "sqli")
    assert f.verdict == base.REJECTED


# --- NoSQL (operatör enjeksiyonu, error-based differential) ---

def nosql_vuln(request):
    val = _injected(request)
    if "$ne" in val or "$gt" in val:
        return httpx.Response(500, text="MongoError: unknown operator: $ne")
    return httpx.Response(200, json={"id": val})


def nosql_safe(request):
    return httpx.Response(200, json={"id": _injected(request)})


@pytest.mark.asyncio
async def test_nosql_confirmed_on_operator_error_differential():
    f = await _find(nosql_vuln, "nosqli")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.negative_control is True   # benign temizdi, operatör hata verdi


@pytest.mark.asyncio
async def test_nosql_rejected_without_error():
    f = await _find(nosql_safe, "nosqli")
    assert f.verdict == base.REJECTED


# --- NoSQL (JSON GÖVDESİNDE yapısal operatör — crAPI coupon_code sınıfı) ---

_BODY_EP = Endpoint(method="POST", path_template="/api/coupon/validate",
                    id_param="coupon_code", id_location="body")


def _body_field(request):
    import json
    try:
        return json.loads((request.content or b"").decode("utf-8", "replace")).get("coupon_code")
    except Exception:
        return None


@pytest.mark.asyncio
async def test_nosql_injects_structured_operator_object_in_json_body():
    # Enjeksiyon isteği operatörü NESNE olarak gömmeli ({"$ne": null}), tırnaklı string DEĞİL —
    # aksi halde Mongo değeri literal sayar ve enjeksiyon hiç tetiklenmez.
    seen: list = []

    def handler(request):
        if request.method == "POST":
            seen.append(_body_field(request))
            v = _body_field(request)
            if isinstance(v, dict) and "$ne" in v:
                return httpx.Response(500, text="MongoServerError: unknown operator: $ne")
        return httpx.Response(200, json={"valid": False})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    oracle = InjectionOracle(Replayer(PolicyEngine(scope)), BASE)
    fs = await oracle.test_param(_BODY_EP, s, param="coupon_code", location="body")
    await store.aclose_all()
    f = next(x for x in fs if x.type == "nosqli")
    assert f.verdict == base.CONFIRMED and f.evidence.negative_control is True
    # gövdeye en az bir kez yapısal operatör nesnesi gönderildi (tırnaklı string değil)
    assert any(isinstance(v, dict) and "$ne" in v for v in seen)


@pytest.mark.asyncio
async def test_nosql_body_rejected_when_value_coerced_to_string():
    def handler(request):
        if request.method == "POST" and isinstance(_body_field(request), dict):
            return httpx.Response(400, json={"error": "coupon_code must be a string"})
        return httpx.Response(200, json={"valid": False})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    oracle = InjectionOracle(Replayer(PolicyEngine(scope)), BASE)
    fs = await oracle.test_param(_BODY_EP, s, param="coupon_code", location="body")
    await store.aclose_all()
    assert next(x for x in fs if x.type == "nosqli").verdict == base.REJECTED


@pytest.mark.asyncio
async def test_nosql_boolean_confirmed_without_error_signature():
    # Canlı crAPI davranışı: literal ve $eq → 500 {}, $ne → 200 gerçek kupon (hata imzası YOK).
    def handler(request):
        v = _body_field(request)
        if isinstance(v, dict):
            if "$ne" in v and v["$ne"] is not None:
                return httpx.Response(200, json={"coupon_code": "TRIAL10", "discount": 10})
            if "$eq" in v:
                return httpx.Response(500, json={})
        return httpx.Response(500, json={})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    oracle = InjectionOracle(Replayer(PolicyEngine(scope)), BASE)
    fs = await oracle.test_param(_BODY_EP, s, param="coupon_code", location="body")
    await store.aclose_all()
    f = next(x for x in fs if x.type == "nosqli")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers and "TRIAL10" not in f.evidence.leaked_markers[0]


@pytest.mark.asyncio
async def test_nosql_boolean_rejected_when_every_dict_returns_200():
    # Near-miss: sunucu her dict'e (hem $eq hem $ne) 200 döner → $eq literal'le aynı değil → FP yok.
    def handler(request):
        v = _body_field(request)
        if isinstance(v, dict):
            return httpx.Response(200, json={"coupon_code": "TRIAL10", "discount": 10})
        return httpx.Response(500, json={})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    oracle = InjectionOracle(Replayer(PolicyEngine(scope)), BASE)
    fs = await oracle.test_param(_BODY_EP, s, param="coupon_code", location="body")
    await store.aclose_all()
    assert next(x for x in fs if x.type == "nosqli").verdict != base.CONFIRMED


@pytest.mark.asyncio
async def test_nosql_boolean_not_confirmed_when_literals_unstable():
    calls = {"n": 0}

    def handler(request):
        v = _body_field(request)
        if isinstance(v, dict):
            if "$ne" in v:
                return httpx.Response(200, json={"coupon_code": "TRIAL10"})
            return httpx.Response(500, json={})
        calls["n"] += 1
        # İlk literal 500, ikinci literal 200 → kararsız baseline
        return httpx.Response(500 if calls["n"] % 2 == 1 else 200, json={"n": calls["n"]})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    oracle = InjectionOracle(Replayer(PolicyEngine(scope)), BASE)
    fs = await oracle.test_param(_BODY_EP, s, param="coupon_code", location="body")
    await store.aclose_all()
    assert next(x for x in fs if x.type == "nosqli").verdict != base.CONFIRMED


@pytest.mark.asyncio
async def test_nosql_boolean_not_confirmed_when_ne_echoes_probe_value():
    def handler(request):
        v = _body_field(request)
        if isinstance(v, dict):
            if "$ne" in v and v["$ne"] is not None:
                return httpx.Response(200, json={"echo": v["$ne"]})   # yankı → DB kaydı değil
            return httpx.Response(500, json={})
        return httpx.Response(500, json={})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    oracle = InjectionOracle(Replayer(PolicyEngine(scope)), BASE)
    fs = await oracle.test_param(_BODY_EP, s, param="coupon_code", location="body")
    await store.aclose_all()
    assert next(x for x in fs if x.type == "nosqli").verdict != base.CONFIRMED


@pytest.mark.asyncio
async def test_nosql_boolean_not_tried_on_query_parameter():
    seen_urls: list[str] = []

    def handler(request):
        seen_urls.append(unquote(str(request.url)))
        return httpx.Response(200, json={"ok": True})

    q_ep = Endpoint(method="GET", path_template="/api/items", id_param="q", id_location="query")
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    oracle = InjectionOracle(Replayer(PolicyEngine(scope)), BASE)
    fs = await oracle.test_param(q_ep, s, param="q", location="query")
    await store.aclose_all()
    assert next(x for x in fs if x.type == "nosqli").verdict == base.REJECTED
    assert not any("$eq" in u for u in seen_urls)


# --- SSTI (aritmetik değerlendirme kanıtı) ---

_MUL = re.compile(r"(\d{3,})\D{1,3}(\d{3,})")  # {{a*b}} / ${a*b} / #{a*b} içinden a,b


def ssti_vuln(request):
    m = _MUL.search(_injected(request))
    if m:
        product = int(m.group(1)) * int(m.group(2))
        return httpx.Response(200, text=f"<html>Sonuc: {product}</html>")  # ifade DEĞİL çarpım
    return httpx.Response(200, text="<html>yok</html>")


def ssti_safe(request):
    return httpx.Response(200, text=f"<html>Sonuc: {_injected(request)}</html>")  # ham yansıma


@pytest.mark.asyncio
async def test_ssti_confirmed_when_expression_evaluated():
    f = await _find(ssti_vuln, "ssti")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers


@pytest.mark.asyncio
async def test_ssti_rejected_when_only_reflected():
    f = await _find(ssti_safe, "ssti")
    assert f.verdict == base.REJECTED


# --- Path Traversal / LFI (sistem dosyası imzası) ---

def lfi_vuln(request):
    val = _injected(request).lower()
    if "passwd" in val or "win.ini" in val or "%2e" in val:
        return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon")
    return httpx.Response(200, text="ok")


def lfi_safe(request):
    return httpx.Response(200, text="ok")   # dosya sızıntısı yok


@pytest.mark.asyncio
async def test_traversal_confirmed_on_passwd_signature():
    f = await _find(lfi_vuln, "path_traversal")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.leaked_markers   # yalnızca imza etiketi (ham içerik değil)


@pytest.mark.asyncio
async def test_traversal_rejected_without_signature():
    f = await _find(lfi_safe, "path_traversal")
    assert f.verdict == base.REJECTED
