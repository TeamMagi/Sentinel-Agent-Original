"""T1 — SafeActionPolicy + SafeValueGenerator (saf, ağsız; PolicyEngine sahte değil)."""
import re

import pytest

from pentestai.models import Scope
from pentestai.policy import PolicyEngine
from pentestai.recon.browser import SafeActionPolicy, SafeValueGenerator

BASE = "http://localhost:3000"


def _policy(**kwargs: object) -> SafeActionPolicy:
    scope = Scope(
        allowed_hosts=["localhost"], allowed_ports=[3000],
        allowed_path_prefixes=["/api/"], discovery_path_prefixes=["/"],
        allowed_methods=["GET", "HEAD", "POST"],
        safe_write_paths=["/api/coupon/validate"],
        **kwargs,  # type: ignore[arg-type]
    )
    return SafeActionPolicy(PolicyEngine(scope))


@pytest.mark.parametrize("label,destructive", [
    ("Address", False),
    ("Shopping cart", False),
    ("Delete item", True),
    ("Sepetten kaldır", True),
    ("Oturumu kapat", True),
    ("Log out", True),
    ("sign-out", True),
    ("Ödeme yap", True),
    ("Reset password", True),
    ("Cancelled orders", False),
])
def test_destructive_labels_are_word_boundary_aware(label, destructive):
    assert _policy().is_destructive_label(label) is destructive


def test_get_discovery_prefix_allowed():
    allowed, reason = _policy().allow_request("GET", f"{BASE}/")
    assert allowed is True and reason == ""
    assert _policy().allow_request("GET", f"{BASE}/api/orders")[0] is True


def test_discovery_prefix_not_reused_for_test_purpose():
    # '/' yalnız discovery öneki; yazma amacıyla kullanılamaz (PolicyEngine kapısı).
    allowed, reason = _policy(destructive_tests=True).allow_request("POST", f"{BASE}/")
    assert allowed is False and "kapsam dışında" in reason


def test_unlisted_post_blocked_with_turkish_reason():
    allowed, reason = _policy().allow_request("POST", f"{BASE}/api/orders")
    assert allowed is False
    assert "yıkıcı yazma isteği kapalı" in reason
    assert "destructive method blocked" not in reason


def test_safe_write_path_post_allowed():
    allowed, reason = _policy().allow_request("POST", f"{BASE}/api/coupon/validate")
    assert allowed is True and reason == ""


def test_destructive_path_denied_even_for_get():
    for path in ("/logout", "/api/users/delete", "/api/users/7/remove"):
        allowed, reason = _policy().allow_request("GET", BASE + path)
        assert allowed is False and "yıkıcı yol" in reason


def test_form_submit_checks_button_then_request():
    policy = _policy()
    assert policy.allow_form_submit("POST", f"{BASE}/api/orders", "Sepetten kaldır") == (
        False, "yıkıcı form eylemi — buton etiketi güvenli değil",
    )
    assert policy.allow_form_submit("POST", f"{BASE}/api/orders", "Gönder")[0] is False
    assert policy.allow_form_submit("POST", f"{BASE}/api/coupon/validate", "Uygula")[0] is True


@pytest.mark.parametrize("input_type,name,expected", [
    ("email", "", r"snt_[0-9a-f]{8}@example\.invalid"),
    ("text", "E-mail adresi", r"snt_[0-9a-f]{8}@example\.invalid"),
    ("url", "", r"https://example\.invalid/snt_[0-9a-f]{8}"),
    ("number", "qty", r"^1$"),
    ("range", "score", r"^1$"),
    ("tel", "phone", r"^5550000000$"),
    ("date", "born", r"^2020-01-01$"),
    ("password", "pwd", r"^Snt_[0-9a-f]{8}!9$"),
    ("textarea", "note", r"^snt_[0-9a-f]{8}$"),
    ("search", "q", r"^snt_[0-9a-f]{8}$"),
    ("", "", r"^snt_[0-9a-f]{8}$"),
])
def test_safe_value_generator_by_type(input_type, name, expected):
    value = SafeValueGenerator(seed=7).value_for(input_type, name)
    assert re.fullmatch(expected, value)


def test_safe_value_generator_seed_is_deterministic():
    assert (SafeValueGenerator(seed=42).value_for("text")
            == SafeValueGenerator(seed=42).value_for("text"))
    generator = SafeValueGenerator(seed=42)
    assert generator.value_for("text") != generator.value_for("text")
