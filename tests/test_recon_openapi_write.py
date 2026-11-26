"""OpenApiRecon — yazma methodları + requestBody → body_template."""
from pentestai.recon import OpenApiRecon
from pentestai.recon.openapi import ALL_METHODS, READ_METHODS

SPEC = {
    "paths": {
        "/menu/{id}": {"get": {}, "put": {}, "delete": {}, "patch": {}, "options": {}, "trace": {}},
        "/users": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/User"}}}}}},
    },
    "components": {"schemas": {
        "User": {"type": "object", "properties": {
            "username": {"type": "string"},
            "email": {"type": "string", "format": "email"},
            "contact": {"type": "string", "format": "email"},
            "password": {"type": "string"},
            "age": {"type": "integer"},
            "score": {"type": "number"},
            "active": {"type": "boolean"},
            "role": {"type": "string", "enum": ["user", "admin"]},
            "address": {"$ref": "#/components/schemas/Address"},
            "tags": {"type": "array", "items": {"type": "string"}},
        }},
        "Address": {"type": "object", "properties": {
            "city": {"type": "string"}, "geo": {"$ref": "#/components/schemas/Geo"}}},
        "Geo": {"type": "object", "properties": {
            "lat": {"type": "number"}, "deep": {"$ref": "#/components/schemas/Deep"}}},
        "Deep": {"type": "object", "properties": {"x": {"type": "integer"}}},
    }},
}


def test_constants_keep_backward_compat():
    assert READ_METHODS == ("get", "head")
    assert "options" not in ALL_METHODS and "trace" not in ALL_METHODS


def test_write_methods_loaded_options_trace_not():
    methods = {e.method for e in OpenApiRecon().parse(SPEC) if e.path_template == "/menu/{id}"}
    assert methods == {"GET", "PUT", "DELETE", "PATCH"}


def test_read_only_override_still_works():
    eps = OpenApiRecon(methods=READ_METHODS).parse(SPEC)
    assert {e.method for e in eps} == {"GET"}


def test_body_template_from_request_body():
    ep = next(e for e in OpenApiRecon().parse(SPEC) if e.method == "POST")
    body = ep.body_template
    assert body["username"] == "snt_{rand}"
    assert body["email"] == "snt_{rand}@example.com"
    assert body["contact"] == "snt_{rand}@example.com"
    assert body["password"] == "snt_password_sentinel"
    assert body["age"] == 1 and body["score"] == 1
    assert body["active"] is False
    assert body["role"] == "user"
    assert body["tags"] == ["snt_{rand}"]
    # iç içe $ref: User(1) → Address(2) → Geo(3) çözülür; Deep(4) derinlik sınırında atlanır
    assert body["address"]["city"] == "snt_{rand}"
    assert body["address"]["geo"]["lat"] == 1
    assert "deep" not in body["address"]["geo"]


def test_no_body_template_without_request_body():
    eps = [e for e in OpenApiRecon().parse(SPEC) if e.path_template == "/menu/{id}"]
    assert all(e.body_template is None for e in eps)
