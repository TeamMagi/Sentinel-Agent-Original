"""Faz 2 / T4 — CLI bayrakları ve Playwright'ın lazily import edilmesi."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from pentestai.cli import _build_browser_discovery, add_scan_arguments
from pentestai.models import Actor, Scope
from pentestai.policy import PolicyEngine
from pentestai.recon.browser.discovery import BrowserDiscovery


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "browser_crawl": False, "agent": False, "loop": False,
        "crawl_pages": 40, "crawl_depth": 3,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_parser_defaults_and_bayraklar():
    parser = argparse.ArgumentParser()
    add_scan_arguments(parser)
    args = parser.parse_args(["--scope", "s", "--actors", "a"])
    assert args.browser_crawl is False
    assert (args.crawl_pages, args.crawl_depth) == (40, 3)
    assert args.crawl_seconds == 180.0
    enabled = parser.parse_args(["--scope", "s", "--actors", "a", "--browser-crawl",
                                 "--crawl-pages", "7", "--crawl-depth", "2"])
    assert enabled.browser_crawl is True
    assert (enabled.crawl_pages, enabled.crawl_depth) == (7, 2)


def test_bayraksiz_veya_agent_loop_durumunda_cephe_kurulmaz(capsys):
    policy = PolicyEngine(Scope(allowed_hosts=["localhost"], allowed_ports=[3000]))
    assert _build_browser_discovery(_args(), [], policy) is None
    assert _build_browser_discovery(_args(agent=True, browser_crawl=True), [], policy) is None
    assert _build_browser_discovery(_args(loop=True, browser_crawl=True), [], policy) is None
    assert "UYARI" in capsys.readouterr().out


def test_browser_local_storage_only_for_own_actor():
    policy = PolicyEngine(Scope(allowed_hosts=["localhost"], allowed_ports=[3000]))
    actor = Actor(name="admin", role="admin")
    pairs = [(actor, {"browser_local_storage": {"token": "{bearer}"}}),
             (Actor(name="user_A"), {})]
    discovery = _build_browser_discovery(
        _args(browser_crawl=True, crawl_pages=7, crawl_depth=2), pairs, policy)
    assert isinstance(discovery, BrowserDiscovery)
    assert discovery.policy is policy
    assert discovery.local_storage == {"admin": {"token": "{bearer}"}}
    crawler = discovery._factory()   # tarayıcı BAŞLATILMADAN yalnız nesne kurulur
    assert (crawler.max_pages, crawler.max_depth) == (7, 2)


def test_crawler_uses_smaller_of_cli_seconds_and_budget_share():
    policy = PolicyEngine(Scope(allowed_hosts=["localhost"], allowed_ports=[3000]))
    discovery = _build_browser_discovery(
        _args(browser_crawl=True, crawl_seconds=180.0), [], policy)
    assert isinstance(discovery, BrowserDiscovery)
    discovery.time_limit_seconds = 30.0   # Scanner: kalan sürenin %25'i
    assert discovery._factory().max_crawl_seconds == 30.0
    discovery.time_limit_seconds = 240.0
    assert discovery._factory().max_crawl_seconds == 180.0   # CLI sınırı kazanır


def test_browser_login_from_actor_credentials_without_leaking_password():
    policy = PolicyEngine(Scope(allowed_hosts=["localhost"], allowed_ports=[3000]))
    actor = Actor(name="a")
    pairs = [(actor, {
        "credentials": {"email": "u@example.invalid", "password": "SIR-123"},
        "browser_login": {"url": "/login", "username_selector": 'input[type="email"]'},
    })]
    discovery = _build_browser_discovery(_args(browser_crawl=True), pairs, policy)
    assert isinstance(discovery, BrowserDiscovery)
    login = discovery.logins["a"]
    assert login.url == "/login"
    assert login.credentials == {"username": "u@example.invalid", "password": "SIR-123"}
    assert "SIR-123" not in repr(login)
    crawler = discovery._factory()
    assert crawler.max_crawl_seconds == 180.0


def test_cli_import_does_not_import_discovery_module():
    """--browser-crawl verilmeden `recon.browser.discovery` import edilmemeli."""
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src") + os.pathsep + env.get("PYTHONPATH", "")
    code = ("import sys; import pentestai.cli; "
            "assert 'pentestai.recon.browser.discovery' not in sys.modules")
    result = subprocess.run([sys.executable, "-c", code], cwd=root, env=env,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
