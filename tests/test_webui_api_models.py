"""WebUI api_models testleri — scope narrowing, redaction, validation."""
import pytest
from pydantic import ValidationError

from pentestai.models import BudgetConfig, CapturedRequest, Scope
from pentestai.policy import Allow, Deny, PolicyEngine
from pentestai.webui.api_models import (
    ActorSpec,
    AuthSpec,
    BudgetSpec,
    EndpointSpec,
    QuickScanRequest,
    ScanRequest,
    ScopeSpec,
    narrow_budget,
    narrow_scope,
)

# ===================== AuthSpec =====================

def test_auth_spec_token_to_cfg():
    spec = AuthSpec(type="token", login_url="/login", email="a@b.com", password="s3cret")
    cfg = spec.to_cfg()
    assert cfg["type"] == "token"
    assert cfg["credentials"]["email"] == "a@b.com"

def test_auth_spec_static_to_cfg():
    spec = AuthSpec(type="static", headers={"X-Key": "abc"}, cookies={"sid": "xyz"})
    cfg = spec.to_cfg()
    assert cfg["type"] == "static"
    assert cfg["headers"]["X-Key"] == "abc"

def test_auth_spec_redacted_masks_password():
    spec = AuthSpec(password="s3cret", headers={"X-Key": "abc"}, cookies={"sid": "xyz"})
    red = spec.redacted()
    assert red.password == "<REDACTED>"
    assert red.headers["X-Key"] == "<REDACTED>"
    assert red.cookies["sid"] == "<REDACTED>"

def test_auth_spec_redacted_no_password():
    spec = AuthSpec(type="token")
    red = spec.redacted()
    assert red.password is None


# ===================== ActorSpec =====================

def test_actor_spec_to_pair():
    spec = ActorSpec(name="alice", role="admin", own_object_ids={"orders": "5"})
    actor, cfg = spec.to_pair()
    assert actor.name == "alice"
    assert actor.role == "admin"
    assert actor.own_object_ids["orders"] == "5"

def test_actor_spec_numeric_ids_stringified():
    spec = ActorSpec(name="bob", own_object_ids={1: 42})
    actor, _ = spec.to_pair()
    assert actor.own_object_ids["1"] == "42"

def test_actor_spec_redacted():
    spec = ActorSpec(name="alice", auth=AuthSpec(password="p@ss"))
    red = spec.redacted()
    assert red.auth.password == "<REDACTED>"
    assert red.name == "alice"


# ===================== EndpointSpec =====================

def test_endpoint_spec_to_endpoint():
    spec = EndpointSpec(method="post", path_template="/api/orders/{id}")
    ep = spec.to_endpoint()
    assert ep.method == "POST"
    assert ep.path_template == "/api/orders/{id}"


# ===================== ScopeSpec =====================

def test_scope_spec_to_scope():
    spec = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000],
                     allowed_methods=["GET", "POST"], destructive_tests=True)
    scope = spec.to_scope()
    assert "localhost" in scope.allowed_hosts
    assert 3000 in scope.allowed_ports
    assert scope.destructive_tests is True


def test_scope_spec_safe_write_paths_reach_core_scope():
    spec = ScopeSpec(allowed_hosts=["localhost"], safe_write_paths=["/api/coupon/validate", "/api/feedbacks*"])
    assert spec.to_scope().safe_write_paths == ["/api/coupon/validate", "/api/feedbacks*"]

def test_scope_spec_safe_write_paths_default_empty():
    assert ScopeSpec().safe_write_paths == []
    assert ScopeSpec().to_scope().safe_write_paths == []

@pytest.mark.parametrize("bad", [[""], ["   "], ["/ok", ""], [None], [5]])
def test_scope_spec_safe_write_paths_invalid_item_rejected(bad):
    with pytest.raises(ValidationError) as exc:
        ScopeSpec(safe_write_paths=bad)
    assert "safe_write_paths" in str(exc.value)

def test_safe_write_paths_does_not_open_put():
    spec = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/api/"],
                     allowed_methods=["GET", "HEAD", "POST", "PUT"], safe_write_paths=["/api/coupon/validate"])
    engine = PolicyEngine(spec.to_scope())
    url = "http://localhost:3000/api/coupon/validate"
    assert isinstance(engine.authorize(CapturedRequest(method="POST", url=url)), Allow)
    assert isinstance(engine.authorize(CapturedRequest(method="PUT", url=url)), Deny)


# ===================== narrow_scope =====================

def test_narrow_scope_safe_write_paths_subset_kept():
    server = _server_scope()
    server.safe_write_paths = ["/api/coupon/validate"]
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/api/"],
                    safe_write_paths=["/API/coupon/validate"])
    result = narrow_scope(server, req)
    assert isinstance(result, ScopeSpec)
    assert result.safe_write_paths == ["/API/coupon/validate"]

def test_narrow_scope_safe_write_paths_beyond_server_rejected():
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/api/"],
                    safe_write_paths=["/api/orders"])
    result = narrow_scope(_server_scope(), req)
    assert isinstance(result, str)
    assert "safe_write_paths" in result

def test_narrow_scope_safe_write_paths_empty_not_inherited():
    server = _server_scope()
    server.safe_write_paths = ["/api/coupon/validate"]
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/api/"])
    result = narrow_scope(server, req)
    assert isinstance(result, ScopeSpec) and result.safe_write_paths == []


def _server_scope():
    return Scope(
        allowed_hosts=["localhost"], allowed_ports=[3000, 8080],
        allowed_path_prefixes=["/api/"], allowed_methods=["GET", "HEAD", "POST"],
        destructive_tests=True, external_network=False,
        max_payload_bytes=1_048_576, no_secrets_in_query=True,
    )

def test_narrow_scope_valid_subset():
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000],
                    allowed_path_prefixes=["/api/v1"], allowed_methods=["GET"])
    result = narrow_scope(_server_scope(), req)
    assert isinstance(result, ScopeSpec)
    assert result.allowed_hosts == ["localhost"]

def test_narrow_scope_extra_host_rejected():
    req = ScopeSpec(allowed_hosts=["localhost", "evil.com"], allowed_ports=[3000])
    result = narrow_scope(_server_scope(), req)
    assert isinstance(result, str)
    assert "allowed_hosts" in result

def test_narrow_scope_extra_port_rejected():
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000, 9999],
                    allowed_path_prefixes=["/api/"], allowed_methods=["GET"])
    result = narrow_scope(_server_scope(), req)
    assert isinstance(result, str)
    assert "allowed_ports" in result

def test_narrow_scope_extra_method_rejected():
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000],
                    allowed_path_prefixes=["/api/"], allowed_methods=["GET", "DELETE"])
    result = narrow_scope(_server_scope(), req)
    assert isinstance(result, str)
    assert "allowed_methods" in result

def test_narrow_scope_destructive_when_server_disallows():
    server = _server_scope()
    server.destructive_tests = False
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000],
                    allowed_path_prefixes=["/api/"], allowed_methods=["GET"],
                    destructive_tests=True)
    result = narrow_scope(server, req)
    assert isinstance(result, str)
    assert "destructive" in result

def test_narrow_scope_path_prefix_outside_server():
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000],
                    allowed_path_prefixes=["/admin/"])
    result = narrow_scope(_server_scope(), req)
    assert isinstance(result, str)
    assert "allowed_path_prefixes" in result

def test_narrow_scope_payload_exceeds():
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000],
                    allowed_path_prefixes=["/api/"], allowed_methods=["GET"],
                    max_payload_bytes=2_000_000)
    result = narrow_scope(_server_scope(), req)
    assert isinstance(result, str)
    assert "max_payload_bytes" in result

def test_narrow_scope_empty_lists_inherit_server():
    req = ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000],
                    allowed_path_prefixes=[], allowed_methods=[])
    result = narrow_scope(_server_scope(), req)
    assert isinstance(result, ScopeSpec)
    assert result.allowed_path_prefixes == ["/api/"]
    assert result.allowed_methods == ["GET", "HEAD", "POST"]


# ===================== narrow_budget =====================

def _server_budget():
    return BudgetConfig(max_total_requests=2000, max_rps_per_host=5.0, max_wall_clock_sec=900)

def test_narrow_budget_valid():
    req = BudgetSpec(max_total_requests=1000, max_rps_per_host=3.0, max_wall_clock_sec=600)
    result = narrow_budget(_server_budget(), req)
    assert isinstance(result, BudgetSpec)

def test_narrow_budget_requests_exceeds():
    req = BudgetSpec(max_total_requests=5000)
    result = narrow_budget(_server_budget(), req)
    assert isinstance(result, str)
    assert "max_total_requests" in result

def test_narrow_budget_rps_exceeds():
    req = BudgetSpec(max_rps_per_host=10.0)
    result = narrow_budget(_server_budget(), req)
    assert isinstance(result, str)
    assert "max_rps_per_host" in result

def test_narrow_budget_wall_clock_exceeds():
    req = BudgetSpec(max_wall_clock_sec=1800)
    result = narrow_budget(_server_budget(), req)
    assert isinstance(result, str)
    assert "max_wall_clock_sec" in result


# ===================== ScanRequest =====================

def test_scan_request_valid():
    req = ScanRequest(
        target="http://localhost:3000",
        scope=ScopeSpec(allowed_hosts=["localhost"]),
        actors=[ActorSpec(name="alice")],
        endpoints=[EndpointSpec(path_template="/api/orders/{id}")],
    )
    assert req.validate_request() is None

def test_scan_request_no_target():
    req = ScanRequest(target="", actors=[ActorSpec(name="a")],
                      endpoints=[EndpointSpec(path_template="/x")])
    assert req.validate_request() is not None

def test_scan_request_no_actors():
    req = ScanRequest(target="http://localhost:3000",
                      scope=ScopeSpec(allowed_hosts=["localhost"]),
                      endpoints=[EndpointSpec(path_template="/x")])
    assert req.validate_request() is not None

def test_scan_request_no_endpoints():
    req = ScanRequest(target="http://localhost:3000",
                      scope=ScopeSpec(allowed_hosts=["localhost"]),
                      actors=[ActorSpec(name="a")])
    assert req.validate_request() is not None

def test_scan_request_host_not_in_scope():
    req = ScanRequest(target="http://evil.com",
                      scope=ScopeSpec(allowed_hosts=["localhost"]),
                      actors=[ActorSpec(name="a")],
                      endpoints=[EndpointSpec(path_template="/x")])
    assert req.validate_request() is not None

def test_scan_request_redacted():
    req = ScanRequest(
        target="http://localhost:3000",
        actors=[ActorSpec(name="alice", auth=AuthSpec(password="secret"))],
        endpoints=[EndpointSpec(path_template="/x")],
    )
    red = req.redacted()
    assert red["actors"][0]["auth"]["password"] == "<REDACTED>"


# ===================== QuickScanRequest =====================

def test_quickscan_valid():
    req = QuickScanRequest(url="https://example.com/page")
    assert req.validate_request() is None
    assert req.target == "https://example.com"

def test_quickscan_no_url():
    req = QuickScanRequest(url="")
    assert req.validate_request() is not None

def test_quickscan_bad_scheme():
    req = QuickScanRequest(url="ftp://example.com")
    assert req.validate_request() is not None

def test_quickscan_derived_scope():
    req = QuickScanRequest(url="https://example.com:8443/path")
    scope = req.derived_scope(external_network=False)
    assert scope.allowed_hosts == ["example.com"]
    assert scope.allowed_ports == [8443]
    assert scope.destructive_tests is False
    assert "GET" in scope.allowed_methods
