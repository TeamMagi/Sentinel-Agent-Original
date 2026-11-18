"""`config/flows.yaml` yükleyicisi ve `FlowConfig` modeli — ağsız, saf parse testleri."""
from pathlib import Path

from pentestai.config import load_flows
from pentestai.models.flows import FlowConfig

EXAMPLE = Path(__file__).resolve().parents[1] / "config" / "flows.example.yaml"


def test_bos_yol_bos_config():
    """None/olmayan dosya → boş config (opsiyonel, geriye uyumlu)."""
    fc = load_flows(None)
    assert isinstance(fc, FlowConfig) and fc.is_empty
    fc2 = load_flows("config/yok-boyle-dosya.yaml")
    assert fc2.is_empty


def test_ornek_config_parse():
    """Örnek dosya tipli olarak yüklenir ve beklenen akışları içerir."""
    fc = load_flows(str(EXAMPLE))
    assert not fc.is_empty
    kinds = {b.kind for b in fc.business_logic}
    assert kinds == {"negative_amount", "coupon_reuse", "workflow_bypass"}
    assert len(fc.second_order_sqli) == 1
    assert fc.second_order_sqli[0].write_endpoint.method == "POST"
    assert len(fc.account_takeover) == 4
    kinds = {a.kind for a in fc.account_takeover}
    assert kinds == {"mfa_precondition_bypass", "password_reset_reuse",
                     "password_reset_weakness", "otp_replay"}
    mfa = next(a for a in fc.account_takeover if a.kind == "mfa_precondition_bypass")
    assert mfa.pre_mfa_actor == "user_pre_mfa"


def test_kind_siz_eski_mfa_kaydi_geriye_uyumlu():
    """Yeni discriminated union öncesi kayıtlarda `kind` yoktu → MFA varsayılanı korunur."""
    fc = FlowConfig.model_validate({"account_takeover": [{
        "endpoint": {"method": "GET", "path_template": "/api/me"},
        "pre_mfa_actor": "user_pre_mfa"}]})
    assert fc.account_takeover[0].kind == "mfa_precondition_bypass"


def test_negative_amount_alanlari():
    fc = load_flows(str(EXAMPLE))
    na = next(b for b in fc.business_logic if b.kind == "negative_amount")
    assert na.amount_field == "amount" and na.expected_direction == "decrease"
    assert na.bad_value == -50 and na.resource_key == "wallet"
