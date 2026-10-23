"""Olgunluk (maturity) etiketi — `classify.PROVEN_TYPES` / `is_experimental` (GOREVLER.md Görev 2).

Ürün dürüstlüğü: bir tip ancak eval twin'iyle (0-FP kapısından geçen) kanıtlanmışsa "proven".
Bu testler `PROVEN_TYPES`'ı eval twin kataloğuyla SENKRON tutar — biri eklenir/çıkarılır da diğeri
güncellenmezse kırmızı yanar (eval.check_consistency disiplininin maturity karşılığı). Ağ yok.
"""
from pentestai.bench.eval import default_cases
from pentestai.classify import PROVEN_TYPES, TYPE_META, is_experimental


def test_proven_types_eval_twinleriyle_senkron():
    """PROVEN_TYPES, eval'de gerçekten twin'i olan tiplerle birebir eşleşmeli (drift yakalama)."""
    twinli_tipler = {case.vuln_type for case in default_cases()}
    assert twinli_tipler == PROVEN_TYPES, (
        f"senkron bozuldu — yalnız eval'de: {twinli_tipler - PROVEN_TYPES}, "
        f"yalnız PROVEN_TYPES'ta: {PROVEN_TYPES - twinli_tipler}"
    )


def test_proven_tip_experimental_degil():
    for t in PROVEN_TYPES:
        assert not is_experimental(t), f"{t} twin'li ama experimental işaretlendi"


def test_twinsiz_kayitli_tip_experimental():
    """Henüz twin'i olmayan kayıtlı bir tip (ör. ssrf) experimental sayılmalı."""
    assert "ssrf" in TYPE_META
    assert "ssrf" not in PROVEN_TYPES
    assert is_experimental("ssrf")


def test_proven_tipler_tabloda_kayitli():
    """PROVEN_TYPES içindeki her tip classify tablosunda da tanımlı olmalı (tutarlılık)."""
    assert set(TYPE_META) >= PROVEN_TYPES, f"tabloda olmayan proven tip: {PROVEN_TYPES - set(TYPE_META)}"
