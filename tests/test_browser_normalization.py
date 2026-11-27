"""T5b — canlı taramada görülen uç normalizasyonu açıkları (saf, ağsız)."""
from __future__ import annotations

from pentestai.models import Endpoint
from pentestai.recon.browser import CapturedCall, TrafficToEndpoints
from pentestai.recon.browser.traffic import normalize_api_path
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
HOSTS = ["localhost"]


def _call(path: str, **kwargs: object) -> CapturedCall:
    return CapturedCall(method="GET", url=BASE + path, status=200,
                        content_type="application/json", **kwargs)  # type: ignore[arg-type]


def test_trailing_slash_is_not_a_separate_endpoint():
    endpoints = TrafficToEndpoints(HOSTS).convert([
        _call("/api/Feedbacks/"), _call("/api/Feedbacks"),
    ])
    assert len(endpoints) == 1
    assert endpoints[0].path_template == "/api/Feedbacks"


def test_root_slash_is_preserved():
    assert normalize_api_path("/") == "/"
    assert normalize_api_path("/api/orders/") == "/api/orders"


def test_static_and_socket_resources_are_not_endpoints():
    converter = TrafficToEndpoints(HOSTS)
    paths = [
        "/assets/i18n/en.json", "/assets/app.js", "/socket.io/",
        "/sockjs/info", "/favicon.ico", "/i18n/tr.json", "/locales/en.json",
    ]
    assert converter.convert([_call(path) for path in paths]) == []
    assert all(normalize_api_path(path) is None for path in paths)


def test_api_json_endpoint_is_kept():
    endpoints = TrafficToEndpoints(HOSTS).convert([_call("/api/x.json")])
    assert [e.path_template for e in endpoints] == ["/api/x.json"]


def test_scanner_browser_known_key_ignores_trailing_slash():
    with_slash = Endpoint(method="get", path_template="/api/Feedbacks/")
    without = Endpoint(method="GET", path_template="/api/Feedbacks")
    assert Scanner._surface_key(with_slash) != Scanner._surface_key(without)
    assert Scanner._browser_key(with_slash) == Scanner._browser_key(without)
    assert Scanner._browser_key(Endpoint(method="GET", path_template="/")) == ("GET", "/")
