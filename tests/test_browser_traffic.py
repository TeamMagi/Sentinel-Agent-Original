"""T1 — CapturedCall → Endpoint dönüşümü (saf, ağsız). Ham JSON değerleri uçlara sızmaz."""
import pytest

from pentestai.recon.browser import CapturedCall, TrafficToEndpoints

BASE = "http://localhost:3000"
HOSTS = ["localhost"]


def _call(method: str, path: str, **kwargs: object) -> CapturedCall:
    return CapturedCall(method=method, url=BASE + path, **kwargs)  # type: ignore[arg-type]


def _convert(calls: list[CapturedCall]) -> list:
    return TrafficToEndpoints(HOSTS).convert(calls)


def test_id_segment_templatized_and_typed():
    endpoints = _convert([_call("GET", "/api/orders/42", status=200,
                                content_type="application/json", response_json={"id": 42})])
    assert len(endpoints) == 1
    assert endpoints[0].method == "GET"
    assert endpoints[0].path_template == "/api/orders/{id}"
    assert endpoints[0].id_type == "integer"


@pytest.mark.parametrize("path,content_type", [
    ("/static/app.js", "application/javascript"),
    ("/img/logo.png", "image/png"),
    ("/app/font.woff2", "font/woff2"),
    ("/sitemap.xml.map", "application/json"),
    ("/index.html", "text/html; charset=utf-8"),
    ("/api/users", "text/html"),
])
def test_static_and_html_skipped(path, content_type):
    assert _convert([_call("GET", path, content_type=content_type)]) == []


def test_other_host_skipped():
    call = CapturedCall(method="GET", url="https://evil.test/api/users",
                        content_type="application/json")
    assert _convert([call]) == []


def test_aborted_post_becomes_endpoint_with_masked_body():
    call = CapturedCall(
        method="POST", url=f"{BASE}/api/orders", status=None, aborted=True, role="user_A",
        request_json={"password": "ham-sır", "note": "meşru-not", "qty": 2},
    )
    endpoints = _convert([call])
    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.method == "POST" and endpoint.path_template == "/api/orders"
    assert endpoint.body_template is not None
    assert endpoint.body_template["password"] == "snt_{rand}"
    assert endpoint.body_template["note"] == "meşru-not"
    assert endpoint.body_template["qty"] == 2
    assert "ham-sır" not in str(endpoint)


def test_nested_sensitive_keys_masked_and_others_preserved():
    call = _call("PUT", "/api/users/7", content_type="application/json", request_json={
        "user": {"token": "abc", "profile": {"apiKey": "xyz", "otp": "1234", "city": "İzmir"}},
        "items": [{"cardNumber": "4111111111111111", "label": "Card-1"}],
    })
    body = _convert([call])[0].body_template
    assert body is not None
    assert body["user"]["token"] == "snt_{rand}"
    assert body["user"]["profile"]["apiKey"] == "snt_{rand}"
    assert body["user"]["profile"]["otp"] == "snt_{rand}"
    assert body["user"]["profile"]["city"] == "İzmir"
    assert body["items"][0]["cardNumber"] == "snt_{rand}"
    assert body["items"][0]["label"] == "Card-1"


def test_same_endpoint_deduped_and_new_keys_merged():
    calls = [
        _call("POST", "/api/orders", request_json={"a": 1, "profile": {"x": 1}}),
        _call("POST", "/api/orders", request_json={"a": 99, "b": 2, "profile": {"y": 2}}),
    ]
    endpoints = _convert(calls)
    assert len(endpoints) == 1
    assert endpoints[0].body_template == {"a": 1, "profile": {"x": 1, "y": 2}, "b": 2}


def test_query_string_ignored_in_template():
    endpoints = _convert([_call("GET", "/api/orders/42?q=abc", content_type="application/json")])
    assert endpoints[0].path_template == "/api/orders/{id}"


def test_query_string_not_ignored_static_suffix_check():
    # Sorgudaki '.js' statik dosya sayılmaz; yol `/api/search` API olarak kalır.
    endpoints = _convert([_call("GET", "/api/search?q=a.js", content_type="application/json")])
    assert endpoints[0].path_template == "/api/search"


def test_deep_body_does_not_copy_beyond_limit():
    node: dict[str, object] = {"leaf": "korunur"}
    for _ in range(8):
        node = {"nested": node}
    endpoint = _convert([_call("POST", "/api/deep", request_json=node)])[0]
    assert endpoint.body_template is not None
    assert "leaf" not in str(endpoint.body_template)
