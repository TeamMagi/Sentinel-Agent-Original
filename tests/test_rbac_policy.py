"""RbacPolicy / load_rbac birim testleri — ağsız.

Yol eşleştirme (parametre adı, trailing slash, method büyük/küçük harf), default deny/allow
davranışı, `"*"` joker kuralı ve YAML yükleme doğrulaması kapsanır.
"""
from __future__ import annotations

import pytest

from pentestai.config import load_rbac
from pentestai.models import RbacPolicy, RbacRule


def _policy(default: str = "deny") -> RbacPolicy:
    return RbacPolicy(default=default, rules=[
        RbacRule(method="GET", path="/api/admin/users", allow=["admin"]),
        RbacRule(method="GET", path="/api/users/{id}", allow=["user", "admin"]),
        RbacRule(method="GET", path="/api/products", allow=["*"]),
    ])


def test_explicit_match_and_method_case_insensitive():
    allowed, source = _policy().expected_roles("get", "/api/admin/users")
    assert allowed == frozenset({"admin"})
    assert source == "explicit"


def test_path_parameter_name_is_ignored():
    """`{id}` ile `{userId}` aynı uç noktadır."""
    allowed, source = _policy().expected_roles("GET", "/api/users/{userId}")
    assert allowed == frozenset({"user", "admin"})
    assert source == "explicit"


def test_trailing_slash_is_ignored():
    allowed, source = _policy().expected_roles("GET", "/api/admin/users/")
    assert allowed == frozenset({"admin"})
    assert source == "explicit"


def test_star_rule_returns_star():
    allowed, source = _policy().expected_roles("GET", "/api/products")
    assert allowed == frozenset({"*"})
    assert source == "explicit"


def test_default_deny_returns_empty_roles():
    allowed, source = _policy(default="deny").expected_roles("GET", "/api/unknown")
    assert allowed == frozenset()
    assert source == "default"


def test_default_allow_returns_none():
    assert _policy(default="allow").expected_roles("GET", "/api/unknown") is None


def test_load_rbac_valid_file(tmp_path):
    p = tmp_path / "rbac.yaml"
    p.write_text(
        "default: deny\n"
        "rules:\n"
        '  - endpoint: "GET /api/admin/users"\n'
        "    allow: [admin]\n"
        '  - endpoint: "GET /api/users/{id}"\n'
        "    allow: [user, admin]\n"
        '  - endpoint: "GET /api/products"\n'
        '    allow: ["*"]\n',
        encoding="utf-8")
    policy = load_rbac(str(p))
    assert policy.default == "deny"
    assert len(policy.rules) == 3
    assert policy.rules[0].method == "GET"
    assert policy.rules[0].path == "/api/admin/users"
    assert policy.rules[0].allow == ["admin"]
    assert policy.rules[2].allow == ["*"]


def test_load_rbac_rejects_bad_endpoint(tmp_path):
    p = tmp_path / "rbac.yaml"
    p.write_text(
        "default: deny\n"
        "rules:\n"
        '  - endpoint: "GET"\n'
        "    allow: [admin]\n",
        encoding="utf-8")
    with pytest.raises(ValueError, match="endpoint"):
        load_rbac(str(p))


def test_load_rbac_rejects_missing_path(tmp_path):
    p = tmp_path / "rbac.yaml"
    p.write_text(
        "default: deny\n"
        "rules:\n"
        '  - endpoint: "GET api/users"\n'
        "    allow: [admin]\n",
        encoding="utf-8")
    with pytest.raises(ValueError):
        load_rbac(str(p))
