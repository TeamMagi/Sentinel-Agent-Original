"""SessionStore ve Session testleri — aktör izolasyonu ve cookie domain."""
import httpx
import pytest

from pentestai.models import Actor, AuthState
from pentestai.net.session_store import Session, SessionStore, _cookie_domain

# --- _cookie_domain ---

def test_cookie_domain_dotted_host():
    assert _cookie_domain("example.com") == "example.com"

def test_cookie_domain_ipv4():
    assert _cookie_domain("127.0.0.1") == "127.0.0.1"

def test_cookie_domain_localhost():
    assert _cookie_domain("localhost") == "localhost.local"

def test_cookie_domain_docker_service():
    assert _cookie_domain("juice-shop") == "juice-shop.local"

def test_cookie_domain_ipv6_returns_none():
    assert _cookie_domain("::1") is None


# --- SessionStore ---

def test_create_session_returns_session():
    store = SessionStore(base_url="http://localhost:8080")
    actor = Actor(name="alice", role="user")
    session = store.create(actor)
    assert isinstance(session, Session)
    assert session.actor is actor

def test_sessions_are_isolated():
    store = SessionStore(base_url="http://localhost:8080")
    a1 = Actor(name="alice", auth=AuthState(cookies={"sid": "aaa"}))
    a2 = Actor(name="bob", auth=AuthState(cookies={"sid": "bbb"}))
    s1 = store.create(a1)
    s2 = store.create(a2)
    assert s1.client is not s2.client

def test_bind_transport_before_sessions():
    store = SessionStore()
    transport = httpx.MockTransport(lambda req: httpx.Response(200))
    store.bind_transport(transport)
    assert store.transport is transport

def test_bind_transport_after_session_raises():
    store = SessionStore(base_url="http://localhost:8080")
    store.create(Actor(name="alice"))
    with pytest.raises(RuntimeError):
        store.bind_transport(httpx.MockTransport(lambda req: httpx.Response(200)))

@pytest.mark.asyncio
async def test_aclose_all():
    store = SessionStore(base_url="http://localhost:8080")
    store.create(Actor(name="alice"))
    store.create(Actor(name="bob"))
    await store.aclose_all()
    assert len(store._sessions) == 0


# --- Session.refresh_auth ---

@pytest.mark.asyncio
async def test_refresh_auth_no_reauth():
    store = SessionStore(base_url="http://localhost:8080")
    session = store.create(Actor(name="alice"))
    result = await session.refresh_auth()
    assert result is False

@pytest.mark.asyncio
async def test_refresh_auth_success():
    new_state = AuthState(cookies={"sid": "new_token"}, headers={"Authorization": "Bearer new"})
    async def _reauth():
        return new_state
    store = SessionStore(base_url="http://localhost:8080")
    actor = Actor(name="alice")
    session = store.create(actor, reauth=_reauth)
    result = await session.refresh_auth()
    assert result is True
    assert actor.auth is new_state

@pytest.mark.asyncio
async def test_refresh_auth_failure():
    async def _reauth():
        raise ConnectionError("auth server down")
    store = SessionStore(base_url="http://localhost:8080")
    session = store.create(Actor(name="alice"), reauth=_reauth)
    result = await session.refresh_auth()
    assert result is False
