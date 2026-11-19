"""bootstrap_demo — çok-endpoint pivot zincirinin config'e yazıldığını doğrular (ağsız).

Juice Shop `/rest/basket/{id}` cevabındaki `UserId`, expander tarafından `/api/Users/{id}`
pivotuna çevrilir. Bunun için aktörlerin `users` own-id'si ve endpoint'in config'de olması
gerekir; aksi hâlde demo yine basket→basket öz-referansında kalır.
"""
import base64
import json

import yaml

from scripts.bootstrap_demo import _jwt_payload, _write_configs


def test_jwt_payload_reads_claim_without_verification():
    payload = base64.urlsafe_b64encode(
        json.dumps({"data": {"id": 25, "email": "v@example.test"}}).encode()
    ).decode().rstrip("=")
    assert _jwt_payload(f"header.{payload}.signature")["data"]["id"] == 25


def test_write_configs_includes_basket_to_users_pivot(tmp_path):
    _write_configs(tmp_path, "http://juice-shop:3000", 6, 7, 25, 26)

    endpoints = yaml.safe_load((tmp_path / "endpoints.yaml").read_text(encoding="utf-8"))["endpoints"]
    by_path = {e["path_template"]: e for e in endpoints}
    assert by_path["/rest/basket/{id}"]["resource_key"] == "basket"
    assert by_path["/api/Users/{id}"]["resource_key"] == "users"

    actors = yaml.safe_load((tmp_path / "actors.yaml").read_text(encoding="utf-8"))["actors"]
    own = {a["name"]: a["own_object_ids"] for a in actors}
    assert own["user_victim"] == {"basket": "6", "users": "25"}
    assert own["user_attacker"] == {"basket": "7", "users": "26"}

    scope = yaml.safe_load((tmp_path / "scope.yaml").read_text(encoding="utf-8"))
    assert "/api/" in scope["scope"]["allowed_path_prefixes"]
