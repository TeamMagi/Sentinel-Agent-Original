"""WebUI RequestGuard testleri — CSRF/DNS-rebinding kapısı."""
from pentestai.webui.guard import RequestGuard


def _guard():
    return RequestGuard(["127.0.0.1:8080", "localhost:8080"])


def _headers(host="127.0.0.1:8080", ctype="application/json", origin=None):
    h = {"host": host, "content-type": ctype}
    if origin:
        h["origin"] = origin
    return h


# --- Host allowlist ---

def test_valid_host_passes():
    result = _guard().check("GET", "/", _headers(), 0)
    assert result is None

def test_invalid_host_rejected():
    result = _guard().check("GET", "/", _headers(host="evil.com"), 0)
    assert result is not None
    assert result[0] == 403

def test_empty_host_rejected():
    result = _guard().check("GET", "/", {"content-type": "application/json"}, 0)
    assert result is not None
    assert result[0] == 403

def test_localhost_alias_passes():
    result = _guard().check("GET", "/", _headers(host="localhost:8080"), 0)
    assert result is None


# --- Content-Type enforcement ---

def test_post_with_json_passes():
    result = _guard().check("POST", "/api/scan", _headers(), 100)
    assert result is None

def test_post_with_form_rejected():
    result = _guard().check("POST", "/api/scan", _headers(ctype="application/x-www-form-urlencoded"), 100)
    assert result is not None
    assert result[0] == 415

def test_post_with_text_rejected():
    result = _guard().check("POST", "/api/scan", _headers(ctype="text/plain"), 100)
    assert result is not None
    assert result[0] == 415

def test_get_with_any_ctype_passes():
    result = _guard().check("GET", "/", _headers(ctype="text/html"), 0)
    assert result is None

def test_put_requires_json():
    result = _guard().check("PUT", "/api/config", _headers(ctype="multipart/form-data"), 100)
    assert result is not None
    assert result[0] == 415

def test_delete_requires_json():
    result = _guard().check("DELETE", "/api/scan/1", _headers(ctype=""), 0)
    assert result is not None
    assert result[0] == 415


# --- Content-Length ---

def test_negative_content_length():
    result = _guard().check("GET", "/", _headers(), -1)
    assert result is not None
    assert result[0] == 400

def test_oversized_body():
    guard = RequestGuard(["127.0.0.1:8080"], max_body_bytes=1000)
    result = guard.check("POST", "/api/scan", _headers(), 2000)
    assert result is not None
    assert result[0] == 413


# --- Origin validation ---

def test_matching_origin_passes():
    result = _guard().check("POST", "/api/scan", _headers(origin="http://127.0.0.1:8080"), 10)
    assert result is None

def test_mismatched_origin_rejected():
    result = _guard().check("POST", "/api/scan", _headers(origin="http://evil.com"), 10)
    assert result is not None
    assert result[0] == 403

def test_no_origin_passes():
    result = _guard().check("POST", "/api/scan", _headers(), 10)
    assert result is None
