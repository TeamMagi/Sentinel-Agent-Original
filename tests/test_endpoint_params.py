"""Çok-parametreli uç modeli (Faz 3 / T1) — ağsız."""
from __future__ import annotations

from pentestai.models import Endpoint, Param
from pentestai.recon.browser.traffic import CapturedCall, TrafficToEndpoints
from pentestai.recon.har import HarRecon
from pentestai.recon.openapi import OpenApiRecon
from pentestai.scanner import Scanner


def _keys(params: list[Param]) -> list[tuple[str, str]]:
    return [(p.name, p.location) for p in params]


def test_param_defaults():
    p = Param(name="q", location="query")
    assert p.type == "unknown" and p.example is None and not p.required and p.sources == []


def test_all_params_path_template_and_id_dedupe():
    ep = Endpoint(path_template="/api/users/{uid}/orders/{id}", id_param="id")
    assert _keys(ep.all_params()) == [("uid", "path"), ("id", "path")]


def test_all_params_id_in_query_and_body():
    q = Endpoint(path_template="/api/orders", id_param="userId", id_location="query")
    assert _keys(q.all_params()) == [("userId", "query")]
    b = Endpoint(method="POST", path_template="/api/getOrder", id_param="orderId",
                 id_location="body", params=[Param(name="note", location="body")])
    assert _keys(b.all_params()) == [("note", "body"), ("orderId", "body")]
    assert [p.name for p in b.params_at("body")] == ["note", "orderId"]
    assert b.params_at("query") == []


def test_all_params_no_id_endpoint_is_empty():
    assert Endpoint(path_template="/api/health").all_params() == []


def test_all_params_merges_declared_with_id():
    ep = Endpoint(path_template="/a/{id}", id_type="integer",
                  params=[Param(name="id", location="path", type="string", sources=["openapi"])])
    (only,) = ep.all_params()
    assert only.type == "string" and only.required and only.sources == ["openapi"]


def test_merge_params_rules_and_copy():
    base = Endpoint(path_template="/x", params=[
        Param(name="a", location="query", type="unknown", sources=["har"]),
        Param(name="b", location="query", type="string", example="one", required=False)])
    merged = base.merge_params([
        Param(name="a", location="query", type="integer", required=True, example=5,
              sources=["browser", "har"]),
        Param(name="b", location="query", type="integer", example="two"),
        Param(name="a", location="body"),
    ])
    assert merged is not base and len(base.params) == 2          # orijinal değişmez
    by = {(p.name, p.location): p for p in merged.params}
    a = by[("a", "query")]
    assert a.type == "integer" and a.required and a.example == 5
    assert a.sources == ["har", "browser"]
    b = by[("b", "query")]
    assert b.type == "string" and b.example == "one"              # bilinen tip / ilk dolu örnek
    assert ("a", "body") in by and len(by) == 3


def test_surface_params_union_across_sources():
    first = Endpoint(path_template="/api/items/{id}")
    second = Endpoint(path_template="/api/items/{id}",
                      params=[Param(name="page", location="query")])
    assert Scanner._surface_params(second) == ["id", "page"]
    scanner = Scanner.__new__(Scanner)
    scanner.surface_sources = {}
    scanner.surface_params = {}
    scanner.surface_tested = {}
    scanner.surface_tested_params = {}
    scanner.register_surface([first], "config")
    scanner.register_surface([second], "har")
    assert scanner.surface_params[("GET", "/api/items/{id}")] == ["id", "page"]
    scanner._record_tested(Endpoint(path_template="/api/items/{id}",
                                    params=[Param(name="sort", location="query")]), "idor")
    assert scanner.surface_params[("GET", "/api/items/{id}")] == ["id", "page", "sort"]
    (entry,) = scanner._surface_entries()
    assert entry.params == ["id", "page", "sort"]


SPEC = {
    "paths": {
        "/api/orders/{orderId}": {
            "parameters": [{"name": "orderId", "in": "path", "required": True,
                            "schema": {"type": "integer"}}],
            "put": {
                "parameters": [
                    {"name": "expand", "in": "query", "schema": {"type": "string",
                                                                 "enum": ["items", "all"]}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer",
                                                                "example": 20}},
                    {"name": "X-Tenant", "in": "header", "schema": {"type": "string"}},
                    {"name": "Authorization", "in": "header", "schema": {"type": "string"}},
                ],
                "requestBody": {"content": {"application/json": {"schema": {
                    "$ref": "#/components/schemas/Order"}}}},
            },
        }
    },
    "components": {"schemas": {"Order": {
        "type": "object", "required": ["status"],
        "properties": {"status": {"type": "string", "enum": ["new", "paid"]},
                       "qty": {"type": "integer"},
                       "secret": {"type": "string", "example": "hunter2"}}}}},
}


def test_openapi_populates_params():
    eps = [e for e in OpenApiRecon().parse(SPEC) if e.method == "PUT"
           and e.id_location == "path"]
    (ep,) = eps
    by = {(p.name, p.location): p for p in ep.params}
    assert by[("orderId", "path")].type == "integer" and by[("orderId", "path")].required
    assert by[("expand", "query")].example == "items"
    assert by[("limit", "query")].example == 20
    assert ("X-Tenant", "header") in by and ("Authorization", "header") not in by
    assert by[("status", "body")].required and by[("status", "body")].example == "new"
    assert by[("qty", "body")].type == "integer"
    assert by[("secret", "body")].example is None                 # string example kopyalanmaz
    assert all(p.sources == ["openapi"] for p in ep.params)


def _har(entries):
    return {"log": {"entries": entries}}


def _entry(url, method="GET", body=None):
    req = {"method": method, "url": url}
    if body is not None:
        req["postData"] = {"mimeType": "application/json", "text": body}
    return {"request": req, "response": {"content": {"mimeType": "application/json"}}}


def test_har_populates_params_without_values():
    har = _har([
        _entry("http://t/api/orders/12?page=3&token=SECRETVAL"),
        _entry("http://t/api/orders/13?sort=asc"),
        _entry("http://t/api/orders", "POST", '{"title": "hello", "qty": 2, "tags": []}'),
    ])
    eps = {(e.method, e.path_template): e for e in HarRecon().parse(har)}
    get = eps[("GET", "/api/orders/{id}")]
    by = {(p.name, p.location): p for p in get.params}
    assert {"page", "token", "sort"} <= {n for n, _ in by}          # ikinci istekten birleşti
    post = {(p.name, p.location): p for p in eps[("POST", "/api/orders")].params}
    assert post[("qty", "body")].type == "integer" and post[("tags", "body")].type == "array"
    dumped = repr([e.model_dump() for e in eps.values()])
    assert "SECRETVAL" not in dumped and "hello" not in dumped
    assert all(p.example is None for e in eps.values() for p in e.params)


def test_traffic_populates_params_without_values():
    calls = [
        CapturedCall(method="GET", url="http://t/api/items/5?filter=x&page=2",
                     content_type="application/json", status=200),
        CapturedCall(method="GET", url="http://t/api/items/6?sort=asc",
                     content_type="application/json", status=200),
        CapturedCall(method="POST", url="http://t/api/items", content_type="application/json",
                     request_json={"title": "hello", "password": "pw123", "n": 1}),
    ]
    eps = {(e.method, e.path_template): e
           for e in TrafficToEndpoints(["t"]).convert(calls)}
    get = eps[("GET", "/api/items/{id}")]
    assert {n for n, loc in _keys(get.params) if loc == "query"} == {"filter", "page", "sort"}
    post = {(p.name, p.location): p for p in eps[("POST", "/api/items")].params}
    assert post[("password", "body")].type == "string" and post[("n", "body")].type == "integer"
    assert all(p.example is None for e in eps.values() for p in e.params)
    assert "pw123" not in repr([e.model_dump() for e in eps.values()])
    assert all(p.sources == ["browser"] for e in eps.values() for p in e.params)
