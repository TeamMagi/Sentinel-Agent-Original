"""Faz 1 / T2 — OpenAPI/Swagger otomatik bulma kaynağı. Ağsız."""
import json

import httpx

from pentestai.models import Actor, AuthState, BudgetConfig, Scope
from pentestai.net import SessionStore
from pentestai.recon.surface import SpecDiscoverySource, SurfaceContext, default_sources
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
SPA = "<!doctype html><html><body><div id='app'></div>" + "x" * 300 + "</body></html>"

OAS3 = {
    "openapi": "3.0.0",
    "servers": [{"url": "/api/v1"}],
    "paths": {
        "/users/{id}": {"get": {"parameters": [
            {"name": "id", "in": "path", "schema": {"type": "integer"}}]}},
        "/books": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"title": {"type": "string"}}}}}}}},
    },
}
SWAGGER2_YAML = """swagger: "2.0"
basePath: /v2
paths:
  /pets/{petId}:
    get:
      parameters:
        - {name: petId, in: path, type: integer}
"""


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 allowed_methods=["GET", "HEAD", "OPTIONS"])


async def _run(handler):
    scanner = Scanner(BASE, _scope(), BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", auth=AuthState()))
    try:
        return await SpecDiscoverySource().discover(SurfaceContext(scanner.replayer, BASE, session))
    finally:
        await store.aclose_all()


def _site(files: dict, methods=None, spa_fallback=False):
    def handler(request):
        if methods is not None:
            methods.append(request.method)
        body = files.get(request.url.path)
        if body is not None:
            return httpx.Response(200, text=body)
        return httpx.Response(200, text=SPA) if spa_fallback else httpx.Response(404)
    return handler


def _keys(eps):
    return {(e.method, e.path_template) for e in eps}


async def test_openapi3_json_servers_prefix_and_body_template():
    methods: list[str] = []
    eps = await _run(_site({"/openapi.json": json.dumps(OAS3)}, methods))
    assert _keys(eps) == {("GET", "/api/v1/users/{id}"), ("POST", "/api/v1/books")}
    post = next(e for e in eps if e.method == "POST")
    assert post.body_template == {"title": "snt_{rand}"}
    assert set(methods) <= {"GET", "HEAD", "OPTIONS"}


async def test_swagger2_yaml_basepath_prefix():
    eps = await _run(_site({"/swagger.yaml": SWAGGER2_YAML}))
    assert _keys(eps) == {("GET", "/v2/pets/{petId}")}


async def test_swagger_ui_html_points_to_spec():
    html = '<script>SwaggerUIBundle({ url: "/static/spec-x.json", dom_id: "#ui" })</script>'
    eps = await _run(_site({"/swagger-ui/": html, "/static/spec-x.json": json.dumps(OAS3)}))
    assert ("GET", "/api/v1/users/{id}") in _keys(eps)


async def test_swagger_ui_foreign_origin_url_not_followed():
    html = '<script>SwaggerUIBundle({ url: "http://evil.example/spec.json" })</script>'
    methods: list[str] = []
    eps = await _run(_site({"/swagger-ui/": html}, methods))
    assert eps == []


async def test_catch_all_spa_yields_nothing():
    assert await _run(_site({}, spa_fallback=True)) == []


async def test_server_url_other_origin_not_taken():
    spec = {**OAS3, "servers": [{"url": "http://api.other.example/v1"}]}
    assert await _run(_site({"/openapi.json": json.dumps(spec)})) == []


async def test_absolute_same_origin_server_path_used():
    spec = {**OAS3, "servers": [{"url": "http://localhost:3000/rest"}]}
    eps = await _run(_site({"/openapi.json": json.dumps(spec)}))
    assert ("GET", "/rest/users/{id}") in _keys(eps)


async def test_json_without_paths_is_not_spec():
    assert await _run(_site({"/openapi.json": json.dumps({"openapi": "3.0.0"})})) == []


def test_default_sources_spec_first():
    assert isinstance(default_sources()[0], SpecDiscoverySource)
