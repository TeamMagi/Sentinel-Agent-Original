"""TokenAuthProvider — JSON/form/auto login gövde biçimleri.

Network'süz (CLAUDE.md §6): httpx.MockTransport. Auto modu yalnızca 415/422'de form'a düşer;
401/403 yanlış paroladır ve ikinci deneme YAPILMAZ.
"""
import json
from urllib.parse import parse_qs

import httpx
import pytest

from pentestai.auth.provider import AuthError, TokenAuthProvider, build_auth_provider
from pentestai.models import Scope
from pentestai.net.replay import ScopeError
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
LOGIN = f"{BASE}/token"
TOKEN_FROM = {"kind": "bearer", "from": "json:access_token"}
CREDS = {"username": "snt_user", "password": "SuperSecretPassword123"}
TOKEN_OK = {"access_token": "tok-ok"}


def _scope(**kw):
    base = dict(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                allowed_methods=["GET", "HEAD"], destructive_tests=False)
    base.update(kw)
    return Scope(**base)


def _provider(handler, **kw):
    return TokenAuthProvider(
        LOGIN, dict(CREDS), dict(TOKEN_FROM),
        transport=httpx.MockTransport(handler), **kw,
    )


def _is_json(request):
    return request.headers.get("content-type", "").startswith("application/json")


def _is_form(request):
    return request.headers.get("content-type", "").startswith(
        "application/x-www-form-urlencoded")


# --------------------------- açık modlar ---------------------------

@pytest.mark.asyncio
async def test_json_mode_sends_one_json_request():
    calls = []

    def handler(request):
        calls.append(request)
        assert _is_json(request)
        assert json.loads(request.content) == CREDS
        return httpx.Response(200, json=TOKEN_OK)

    provider = _provider(handler, body_format="json")
    state = await provider.acquire()

    assert state.headers == {"Authorization": "Bearer tok-ok"}
    assert len(calls) == 1
    assert provider.resolved_body_format == "json"


@pytest.mark.asyncio
async def test_form_mode_sends_urlencoded_body_with_extra_fields():
    calls = []

    def handler(request):
        calls.append(request)
        assert _is_form(request)
        form = parse_qs(request.content.decode("utf-8"))
        assert form["username"] == ["snt_user"]
        assert form["password"] == ["SuperSecretPassword123"]
        assert form["grant_type"] == ["password"]
        assert form["scope"] == ["read"]
        return httpx.Response(200, json=TOKEN_OK)

    provider = _provider(
        handler, body_format="form",
        extra_form_fields={"grant_type": "password", "scope": "read"},
    )
    state = await provider.acquire()

    assert state.headers == {"Authorization": "Bearer tok-ok"}
    assert len(calls) == 1
    assert provider.resolved_body_format == "form"


# --------------------------- auto: başarılı yollar ---------------------------

@pytest.mark.asyncio
async def test_auto_falls_back_to_form_on_422():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            assert _is_json(request)
            return httpx.Response(422, json={"detail": "form bekleniyor"})
        assert _is_form(request)
        return httpx.Response(200, json=TOKEN_OK)

    provider = _provider(handler)
    state = await provider.acquire()

    assert state.headers == {"Authorization": "Bearer tok-ok"}
    assert len(calls) == 2
    assert _is_json(calls[0]) and _is_form(calls[1])
    assert provider.resolved_body_format == "form"


@pytest.mark.asyncio
async def test_auto_falls_back_to_form_on_415():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(415, json={"detail": "unsupported media type"})
        assert _is_form(request)
        return httpx.Response(200, json=TOKEN_OK)

    provider = _provider(handler)
    state = await provider.acquire()

    assert state.headers == {"Authorization": "Bearer tok-ok"}
    assert len(calls) == 2
    assert _is_form(calls[1])
    assert provider.resolved_body_format == "form"


@pytest.mark.asyncio
async def test_auto_json_success_makes_only_one_request():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=TOKEN_OK)

    provider = _provider(handler)
    state = await provider.acquire()

    assert state.headers == {"Authorization": "Bearer tok-ok"}
    assert len(calls) == 1
    assert provider.resolved_body_format == "json"


@pytest.mark.asyncio
async def test_auto_resolved_form_is_reused_on_relogin():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(422, json={"detail": "form bekleniyor"})
        assert _is_form(request)
        return httpx.Response(200, json=TOKEN_OK)

    provider = _provider(handler)
    await provider.acquire()
    assert provider.resolved_body_format == "form"

    # Token yenileme/yeniden-login: çözülmüş biçim doğrudan kullanılmalı (JSON denenmemeli).
    await provider.acquire()
    assert len(calls) == 3
    assert _is_form(calls[2])


# --------------------------- auto: hata yolları ---------------------------

@pytest.mark.asyncio
async def test_auto_401_does_not_try_form():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(401, json={"detail": "yanlış parola"})

    provider = _provider(handler)
    with pytest.raises(AuthError) as exc_info:
        await provider.acquire()

    assert len(calls) == 1          # form DENENMEDİ (kilitlenme riski)
    assert provider.resolved_body_format is None
    assert CREDS["password"] not in str(exc_info.value)


@pytest.mark.asyncio
async def test_auto_both_fail_mentions_json_and_form_without_leaking_password():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(422, json={"detail": "GovdeSirriXYZ"})

    provider = _provider(handler)
    with pytest.raises(AuthError) as exc_info:
        await provider.acquire()

    msg = str(exc_info.value)
    assert len(calls) == 2
    assert "JSON ve form" in msg
    assert "SuperSecretPassword123" not in msg
    assert "GovdeSirriXYZ" not in msg
    assert provider.resolved_body_format is None


# --------------------------- policy kapısı ---------------------------

@pytest.mark.asyncio
async def test_form_login_request_is_subject_to_scope_policy():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=TOKEN_OK)

    provider = TokenAuthProvider(
        "http://evil.example/token", dict(CREDS), dict(TOKEN_FROM),
        transport=httpx.MockTransport(handler),
        policy=PolicyEngine(_scope()),
        body_format="form",
    )
    with pytest.raises(ScopeError):
        await provider.acquire()

    assert calls == []              # istek hiç gönderilmedi


# --------------------------- factory ---------------------------

def test_build_auth_provider_passes_body_format_and_extra_form_fields():
    provider = build_auth_provider({
        "type": "token", "login_url": LOGIN, "credentials": dict(CREDS),
        "token_location": dict(TOKEN_FROM),
        "body_format": "form",
        "extra_form_fields": {"grant_type": "password"},
    }, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=TOKEN_OK)))

    assert isinstance(provider, TokenAuthProvider)
    assert provider.body_format == "form"
    assert provider.extra_form_fields == {"grant_type": "password"}


def test_build_auth_provider_invalid_body_format_raises_clear_error():
    with pytest.raises(ValueError, match="body_format"):
        build_auth_provider({
            "type": "token", "login_url": LOGIN, "credentials": dict(CREDS),
            "body_format": "xml",
        })
