"""Tek-komut demo için Juice Shop kalibrasyon hesaplarını hazırlar. DESIGN.md §5, §8.

İki hesap (victim/attacker) oluşturur (varsa sorun değil — login zaten çalışır), kurbanın
sepetine bir ürün ekler (leaked-marker için) ve `run_scan`'in doğrudan okuyabileceği
scope/actors/endpoints YAML'larını üretir. `config/*.yaml` (gerçek, git-ignore'lu) dosyalarına
DOKUNMAZ — kendi `--out` dizinine yazar, böylece kullanıcının kendi hedefine karşı kurduğu
config ile çakışmaz.

PIVOT ZİNCİRİ (çok-endpoint demo): `/rest/basket/{id}` cevabı kurbanın `UserId`'sini sızdırır;
`HypothesisExpander` bu referansı bilinen `/api/Users/{id}` endpoint'iyle eşleştirir → orada da
BOLA kanıtlanır. Eski iki-endpoint'li demo yalnızca basket→basket öz-referansı üretiyordu;
kullanıcı kaynağı config'e eklenince pivot gerçekten ikinci bir endpoint'e taşıyor.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import pathlib

import httpx
import yaml

VICTIM = {"email": "sentinel_demo_victim@test.local", "password": "Passw0rd!Victim1"}
ATTACKER = {"email": "sentinel_demo_attacker@test.local", "password": "Passw0rd!Attack1"}


async def _wait_ready(client: httpx.AsyncClient, base_url: str, *, timeout: float = 60.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        try:
            r = await client.get(f"{base_url}/rest/products/search")
            if r.status_code < 500:
                return
        except httpx.TransportError:
            pass
        if asyncio.get_event_loop().time() > deadline:
            raise SystemExit(f"Juice Shop {timeout:.0f}s içinde hazır olmadı: {base_url}")
        await asyncio.sleep(2)


async def _register(client: httpx.AsyncClient, base_url: str, email: str, password: str) -> None:
    await client.post(f"{base_url}/api/Users", json={
        "email": email, "password": password, "passwordRepeat": password,
        "securityQuestion": {"id": 1, "question": "demo"}, "securityAnswer": "demo",
    })   # zaten kayıtlıysa 400 döner — bootstrap idempotent olduğu için görmezden geliriz


def _jwt_payload(token: str) -> dict:
    """İmza doğrulamadan JWT gövdesini okur — yalnızca bootstrap'in kendi token'ındaki
    kullanıcı id'sini öğrenmek için (yetki kararı DEĞİL; tarama tarafı bunu kullanmaz)."""
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


async def _login(client: httpx.AsyncClient, base_url: str,
                 email: str, password: str) -> tuple[str, int, int]:
    r = await client.post(f"{base_url}/rest/user/login", json={"email": email, "password": password})
    r.raise_for_status()
    auth = r.json()["authentication"]
    token = auth["token"]
    # `bid` (sepet) yanıtta hazır; kullanıcı id'si yalnızca JWT claim'lerinde (`data.id`).
    uid = _jwt_payload(token).get("data", {}).get("id")
    if uid is None:
        raise SystemExit("login token'ında kullanıcı id'si (data.id) yok")
    return token, auth["bid"], int(uid)


def _write_configs(out_dir: pathlib.Path, base_url: str, victim_bid: int, attacker_bid: int,
                   victim_uid: int, attacker_uid: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scope.yaml").write_text(yaml.safe_dump({
        "target": {"base_url": base_url},
        "scope": {
            "allowed_hosts": [httpx.URL(base_url).host],
            "allowed_ports": [httpx.URL(base_url).port or 80],
            "allowed_path_prefixes": ["/api/", "/rest/"],
            "denied_path_patterns": ["*/reset*", "*/admin/db*", "*/export*"],
            "allowed_methods": ["GET", "HEAD"],
            "destructive_tests": False,
            "external_network": False,
        },
        # Bütçe, tüm dedektör/oracle ailesinin (idor/bfla/injection/crlf/oauth/jwt-confusion/hpp/…)
        # üç endpoint üzerinde rahatça koşabileceği kadar: 200 artık yetersizdi (rate_limit fazında
        # BudgetExceeded'e düşüyordu). scope.example.yaml ile hizalı.
        "budget": {"max_total_requests": 2000, "max_rps_per_host": 5, "max_wall_clock_sec": 300},
        "privacy": {"no_secrets_in_query": True},
    }, sort_keys=False), encoding="utf-8")

    (out_dir / "actors.yaml").write_text(yaml.safe_dump({"actors": [
        {"name": "user_victim", "role": "user", "auth": {
            "type": "token", "login_url": f"{base_url}/rest/user/login",
            "credentials": VICTIM, "token_location": {"kind": "bearer", "from": "json:authentication.token"},
        }, "own_object_ids": {"basket": str(victim_bid), "users": str(victim_uid)}},
        {"name": "user_attacker", "role": "user", "auth": {
            "type": "token", "login_url": f"{base_url}/rest/user/login",
            "credentials": ATTACKER, "token_location": {"kind": "bearer", "from": "json:authentication.token"},
        }, "own_object_ids": {"basket": str(attacker_bid), "users": str(attacker_uid)}},
    ]}, sort_keys=False), encoding="utf-8")

    (out_dir / "endpoints.yaml").write_text(yaml.safe_dump({"endpoints": [
        {"method": "GET", "path_template": "/rest/basket/{id}", "id_param": "id",
         "id_location": "path", "resource_key": "basket"},
        # Pivot hedefi: basket cevabındaki `UserId` → bu endpoint. Anonim erişim 401,
        # saldırgan kurbanın e-posta/rol kaydını okuyabiliyor → gerçek BOLA (Juice Shop).
        {"method": "GET", "path_template": "/api/Users/{id}", "id_param": "id",
         "id_location": "path", "resource_key": "users"},
        # Juice Shop'un bilinen SQLi yüzeyi: /rest/products/search?q= (error-based, SQLITE_ERROR).
        # injection oracle'ı query-param'da SQLi'yi kanıtlar → demo CONFIRMED kapsamını genişletir.
        {"method": "GET", "path_template": "/rest/products/search", "id_param": "q",
         "id_location": "query", "resource_key": "products"},
    ]}, sort_keys=False), encoding="utf-8")


async def _run(base_url: str, out_dir: pathlib.Path) -> None:
    async with httpx.AsyncClient(timeout=15) as client:
        print(f"[bootstrap] waiting for Juice Shop: {base_url}")
        await _wait_ready(client, base_url)

        print("[bootstrap] creating calibration accounts (skipped if they already exist)")
        await _register(client, base_url, **VICTIM)
        await _register(client, base_url, **ATTACKER)

        victim_token, victim_bid, victim_uid = await _login(client, base_url, **VICTIM)
        _, attacker_bid, attacker_uid = await _login(client, base_url, **ATTACKER)

        print(f"[bootstrap] adding an item to the victim's basket (bid={victim_bid})")
        await client.post(f"{base_url}/api/BasketItems", json={
            "ProductId": 1, "BasketId": victim_bid, "quantity": 3,
        }, headers={"Authorization": f"Bearer {victim_token}"})

        _write_configs(out_dir, base_url, victim_bid, attacker_bid, victim_uid, attacker_uid)
        print(f"[bootstrap] config written: {out_dir}/{{scope,actors,endpoints}}.yaml")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Juice Shop demo hesaplarını + config'ini hazırla")
    p.add_argument("--base-url", default="http://juice-shop:3000")
    p.add_argument("--out", default="runs/demo/config")
    args = p.parse_args(argv)
    asyncio.run(_run(args.base_url, pathlib.Path(args.out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
